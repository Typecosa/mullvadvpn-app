package net.mullvad.mullvadvpn.lib.model

import arrow.optics.optics

@optics
data class WireguardConstraints(
    val port: Constraint<Port>,
    val useMultihop: Boolean,
    val entryLocation: Constraint<RelayItemId>,
) {
    companion object
}
