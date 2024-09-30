use super::{
    AfterDisconnect, ConnectingState, DisconnectingState, ErrorState, EventConsequence,
    EventResult, SharedTunnelStateValues, TunnelCommand, TunnelCommandReceiver, TunnelState,
    TunnelStateTransition,
};
use crate::{
    dns::ResolvedDnsConfig,
    firewall::FirewallPolicy,
    tunnel::{TunnelEvent, TunnelMetadata},
};
use futures::{
    channel::{mpsc, oneshot},
    stream::Fuse,
    StreamExt,
};
use talpid_types::{
    net::{AllowedClients, AllowedEndpoint, TunnelParameters},
    tunnel::{ErrorStateCause, FirewallPolicyError},
    BoxedError, ErrorExt,
};
use tracing::{instrument, Instrument};

#[cfg(windows)]
use crate::tunnel::TunnelMonitor;

use super::connecting_state::TunnelCloseEvent;

pub(crate) type TunnelEventsReceiver =
    Fuse<mpsc::UnboundedReceiver<(TunnelEvent, oneshot::Sender<()>)>>;

/// The tunnel is up and working.
pub struct ConnectedState {
    metadata: TunnelMetadata,
    tunnel_events: TunnelEventsReceiver,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: TunnelCloseEvent,
    tunnel_close_tx: oneshot::Sender<()>,
}

impl ConnectedState {
    #[cfg_attr(target_os = "android", allow(unused_variables))]
    pub(super) fn enter(
        shared_values: &mut SharedTunnelStateValues,
        metadata: TunnelMetadata,
        tunnel_events: TunnelEventsReceiver,
        tunnel_parameters: TunnelParameters,
        tunnel_close_event: TunnelCloseEvent,
        tunnel_close_tx: oneshot::Sender<()>,
    ) -> (Box<dyn TunnelState>, TunnelStateTransition) {
        let connected_state = ConnectedState {
            metadata,
            tunnel_events,
            tunnel_parameters,
            tunnel_close_event,
            tunnel_close_tx,
        };

        let tunnel_interface = Some(connected_state.metadata.interface.clone());
        let tunnel_endpoint = talpid_types::net::TunnelEndpoint {
            tunnel_interface,
            ..connected_state.tunnel_parameters.get_tunnel_endpoint()
        };

        if let Err(error) = connected_state.set_firewall_policy(shared_values) {
            DisconnectingState::enter(
                connected_state.tunnel_close_tx,
                connected_state.tunnel_close_event,
                AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(error)),
            )
        } else if let Err(error) = connected_state.set_dns(shared_values) {
            log::error!("{}", error.display_chain_with_msg("Failed to set DNS"));
            DisconnectingState::enter(
                connected_state.tunnel_close_tx,
                connected_state.tunnel_close_event,
                AfterDisconnect::Block(ErrorStateCause::SetDnsError),
            )
        } else {
            (
                Box::new(connected_state),
                TunnelStateTransition::Connected(tunnel_endpoint),
            )
        }
    }

    fn set_firewall_policy(
        &self,
        shared_values: &mut SharedTunnelStateValues,
    ) -> Result<(), FirewallPolicyError> {
        let policy = self.get_firewall_policy(shared_values);
        shared_values
            .firewall
            .apply_policy(policy)
            .map_err(|error| {
                log::error!(
                    "{}",
                    error.display_chain_with_msg(
                        "Failed to apply firewall policy for connected state"
                    )
                );
                #[cfg(windows)]
                match error {
                    crate::firewall::Error::ApplyingConnectedPolicy(policy_error) => policy_error,
                    _ => FirewallPolicyError::Generic,
                }
                #[cfg(not(windows))]
                FirewallPolicyError::Generic
            })
    }

    fn get_firewall_policy(&self, shared_values: &SharedTunnelStateValues) -> FirewallPolicy {
        let endpoint = self.tunnel_parameters.get_next_hop_endpoint();

        #[cfg(target_os = "windows")]
        let clients = AllowedClients::from(
            TunnelMonitor::get_relay_client(&shared_values.resource_dir, &self.tunnel_parameters)
                .into_iter()
                .collect::<Vec<_>>(),
        );

        #[cfg(not(target_os = "windows"))]
        let clients = if self
            .tunnel_parameters
            .get_openvpn_local_proxy_settings()
            .is_some()
        {
            AllowedClients::All
        } else {
            AllowedClients::Root
        };

        let peer_endpoint = AllowedEndpoint { endpoint, clients };

        #[cfg(target_os = "macos")]
        let redirect_interface = shared_values
            .runtime
            .block_on(shared_values.split_tunnel.interface());

        FirewallPolicy::Connected {
            peer_endpoint,
            tunnel: self.metadata.clone(),
            allow_lan: shared_values.allow_lan,
            #[cfg(not(target_os = "android"))]
            dns_config: Self::resolve_dns(&self.metadata, shared_values),
            #[cfg(target_os = "macos")]
            redirect_interface,
            #[cfg(target_os = "macos")]
            apple_services_bypass: shared_values.apple_services_bypass,
        }
    }

    fn resolve_dns(
        metadata: &TunnelMetadata,
        shared_values: &SharedTunnelStateValues,
    ) -> ResolvedDnsConfig {
        shared_values.dns_config.resolve(&metadata.gateways())
    }

    fn set_dns(&self, shared_values: &mut SharedTunnelStateValues) -> Result<(), BoxedError> {
        let dns_config = Self::resolve_dns(&self.metadata, shared_values);

        shared_values
            .dns_monitor
            .set(&self.metadata.interface, dns_config)
            .map_err(BoxedError::new)?;

        Ok(())
    }

    fn reset_dns(shared_values: &mut SharedTunnelStateValues) {
        if let Err(error) = shared_values.dns_monitor.reset_before_interface_removal() {
            log::error!("{}", error.display_chain_with_msg("Unable to reset DNS"));
        }
    }

    fn reset_routes(
        #[cfg(target_os = "windows")] shared_values: &SharedTunnelStateValues,
        #[cfg(not(target_os = "windows"))] shared_values: &mut SharedTunnelStateValues,
    ) {
        if let Err(error) = shared_values.route_manager.clear_routes() {
            log::error!("{}", error.display_chain_with_msg("Failed to clear routes"));
        }
        #[cfg(target_os = "linux")]
        if let Err(error) = shared_values
            .runtime
            .block_on(shared_values.route_manager.clear_routing_rules())
        {
            log::error!(
                "{}",
                error.display_chain_with_msg("Failed to clear routing rules")
            );
        }
    }

    fn disconnect(
        self,
        shared_values: &mut SharedTunnelStateValues,
        after_disconnect: AfterDisconnect,
    ) -> EventConsequence {
        Self::reset_dns(shared_values);
        Self::reset_routes(shared_values);

        EventConsequence::NewState(DisconnectingState::enter(
            self.tunnel_close_tx,
            self.tunnel_close_event,
            after_disconnect,
        ))
    }

    #[instrument(name = "ConnectedState::handle_commands", skip_all)]
    fn handle_commands(
        self: Box<Self>,
        command: Option<TunnelCommand>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        match command {
            Some(TunnelCommand::AllowLan(allow_lan, complete_tx)) => {
                let consequence = if shared_values.set_allow_lan(allow_lan) {
                    #[cfg(target_os = "android")]
                    {
                        if let Err(_err) = shared_values.restart_tunnel(false) {
                            self.disconnect(
                                shared_values,
                                AfterDisconnect::Block(ErrorStateCause::StartTunnelError),
                            )
                        } else {
                            self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
                        }
                    }
                    #[cfg(not(target_os = "android"))]
                    {
                        match self.set_firewall_policy(shared_values) {
                            Ok(()) => SameState(self),
                            Err(error) => self.disconnect(
                                shared_values,
                                AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(
                                    error,
                                )),
                            ),
                        }
                    }
                } else {
                    SameState(self)
                };

                let _ = complete_tx.send(());
                consequence
            }
            Some(TunnelCommand::AllowEndpoint(endpoint, tx)) => {
                shared_values.allowed_endpoint = endpoint;
                let _ = tx.send(());
                SameState(self)
            }
            Some(TunnelCommand::Dns(servers, complete_tx)) => {
                let consequence = if shared_values.set_dns_config(servers) {
                    #[cfg(target_os = "android")]
                    {
                        if let Err(_err) = shared_values.restart_tunnel(false) {
                            self.disconnect(
                                shared_values,
                                AfterDisconnect::Block(ErrorStateCause::StartTunnelError),
                            )
                        } else {
                            self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
                        }
                    }
                    #[cfg(not(target_os = "android"))]
                    {
                        if let Err(error) = self.set_firewall_policy(shared_values) {
                            return self.disconnect(
                                shared_values,
                                AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(
                                    error,
                                )),
                            );
                        }

                        match self.set_dns(shared_values) {
                            Ok(()) => SameState(self),
                            Err(error) => {
                                log::error!(
                                    "{}",
                                    error.display_chain_with_msg("Failed to set DNS")
                                );
                                self.disconnect(
                                    shared_values,
                                    AfterDisconnect::Block(ErrorStateCause::SetDnsError),
                                )
                            }
                        }
                    }
                } else {
                    SameState(self)
                };
                let _ = complete_tx.send(());
                consequence
            }
            Some(TunnelCommand::BlockWhenDisconnected(block_when_disconnected, complete_tx)) => {
                shared_values.block_when_disconnected = block_when_disconnected;
                let _ = complete_tx.send(());
                SameState(self)
            }
            Some(TunnelCommand::Connectivity(connectivity)) => {
                shared_values.connectivity = connectivity;
                if connectivity.is_offline() {
                    self.disconnect(
                        shared_values,
                        AfterDisconnect::Block(ErrorStateCause::IsOffline),
                    )
                } else {
                    SameState(self)
                }
            }
            Some(TunnelCommand::Connect) => {
                self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
            }
            Some(TunnelCommand::Disconnect) | None => {
                self.disconnect(shared_values, AfterDisconnect::Nothing)
            }
            Some(TunnelCommand::Block(reason)) => {
                self.disconnect(shared_values, AfterDisconnect::Block(reason))
            }
            #[cfg(target_os = "android")]
            Some(TunnelCommand::BypassSocket(fd, done_tx)) => {
                shared_values.bypass_socket(fd, done_tx);
                SameState(self)
            }
            #[cfg(windows)]
            Some(TunnelCommand::SetExcludedApps(result_tx, paths)) => {
                shared_values.exclude_paths(paths, result_tx);
                SameState(self)
            }
            #[cfg(target_os = "android")]
            Some(TunnelCommand::SetExcludedApps(result_tx, paths)) => {
                if shared_values.set_excluded_paths(paths) {
                    if let Err(err) = shared_values.restart_tunnel(false) {
                        let _ =
                            result_tx.send(Err(crate::split_tunnel::Error::SetExcludedApps(err)));
                        self.disconnect(
                            shared_values,
                            AfterDisconnect::Block(ErrorStateCause::SplitTunnelError),
                        )
                    } else {
                        let _ = result_tx.send(Ok(()));
                        self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
                    }
                } else {
                    let _ = result_tx.send(Ok(()));
                    SameState(self)
                }
            }
            #[cfg(target_os = "macos")]
            Some(TunnelCommand::SetExcludedApps(result_tx, paths)) => {
                match shared_values.set_exclude_paths(paths) {
                    Ok(interface_changed) => {
                        let _ = result_tx.send(Ok(()));

                        if interface_changed {
                            if let Err(error) = self.set_firewall_policy(shared_values) {
                                return self.disconnect(
                                    shared_values,
                                    AfterDisconnect::Block(
                                        ErrorStateCause::SetFirewallPolicyError(error),
                                    ),
                                );
                            }
                        }
                    }
                    Err(error) => {
                        let cause = ErrorStateCause::from(&error);
                        let _ = result_tx.send(Err(error));
                        return self.disconnect(shared_values, AfterDisconnect::Block(cause));
                    }
                }
                SameState(self)
            }

            #[cfg(target_os = "macos")]
            Some(TunnelCommand::AppleServicesBypass(complete_tx, apple_services_bypass)) => {
                let consequence = if shared_values.set_apple_services_bypass(apple_services_bypass)
                {
                    match self.set_firewall_policy(shared_values) {
                        Ok(()) => SameState(self),
                        Err(error) => self.disconnect(
                            shared_values,
                            AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(error)),
                        ),
                    }
                } else {
                    SameState(self)
                };

                let _ = complete_tx.send(());
                consequence
            }
        }
    }

    fn handle_tunnel_events(
        self: Box<Self>,
        event: Option<(TunnelEvent, oneshot::Sender<()>)>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        match event {
            Some((TunnelEvent::Down, _)) | None => {
                self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
            }
            Some(_) => SameState(self),
        }
    }

    fn handle_tunnel_close_event(
        self,
        block_reason: Option<ErrorStateCause>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        if let Some(block_reason) = block_reason {
            Self::reset_dns(shared_values);
            Self::reset_routes(shared_values);
            return NewState(ErrorState::enter(shared_values, block_reason));
        }

        log::info!("Tunnel closed. Reconnecting.");
        Self::reset_dns(shared_values);
        Self::reset_routes(shared_values);
        NewState(ConnectingState::enter(shared_values, 0))
    }
}

impl TunnelState for ConnectedState {
    #[tracing::instrument(skip_all, name = "Connected")]
    fn handle_event(
        mut self: Box<Self>,
        runtime: &tokio::runtime::Handle,
        commands: &mut TunnelCommandReceiver,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        let result = runtime.block_on(
            async {
                futures::select! {
                    command = commands.next() => EventResult::Command(command),
                    event = self.tunnel_events.next() => EventResult::Event(event),
                    result = &mut self.tunnel_close_event => EventResult::Close(result),
                }
            }
            .instrument(tracing::info_span!("waiting for event")),
        );

        match result {
            EventResult::Command(command) => self.handle_commands(command, shared_values),
            EventResult::Event(event) => self.handle_tunnel_events(event, shared_values),
            EventResult::Close(result) => {
                if result.is_err() {
                    log::warn!("Tunnel monitor thread has stopped unexpectedly");
                }
                let block_reason = result.unwrap_or(None);
                self.handle_tunnel_close_event(block_reason, shared_values)
            }
        }
    }
}
