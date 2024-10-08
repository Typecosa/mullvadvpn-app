package net.mullvad.mullvadvpn.compose.screen

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.layout
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewParameter
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.generated.destinations.AccountDestination
import com.ramcosta.composedestinations.generated.destinations.DeviceRevokedDestination
import com.ramcosta.composedestinations.generated.destinations.OutOfTimeDestination
import com.ramcosta.composedestinations.generated.destinations.SelectLocationDestination
import com.ramcosta.composedestinations.generated.destinations.SettingsDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.result.ResultRecipient
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.R
import net.mullvad.mullvadvpn.compose.button.ConnectionButton
import net.mullvad.mullvadvpn.compose.button.SwitchLocationButton
import net.mullvad.mullvadvpn.compose.component.ConnectionStatusText
import net.mullvad.mullvadvpn.compose.component.ExpandChevron
import net.mullvad.mullvadvpn.compose.component.MullvadCircularProgressIndicatorLarge
import net.mullvad.mullvadvpn.compose.component.ScaffoldWithTopBarAndDeviceName
import net.mullvad.mullvadvpn.compose.component.connectioninfo.ConnectionDetailPanel
import net.mullvad.mullvadvpn.compose.component.connectioninfo.FeatureIndicatorsPanel
import net.mullvad.mullvadvpn.compose.component.drawVerticalScrollbar
import net.mullvad.mullvadvpn.compose.component.notificationbanner.NotificationBanner
import net.mullvad.mullvadvpn.compose.extensions.createOpenAccountPageHook
import net.mullvad.mullvadvpn.compose.preview.ConnectUiStatePreviewParameterProvider
import net.mullvad.mullvadvpn.compose.state.ConnectUiState
import net.mullvad.mullvadvpn.compose.test.CIRCULAR_PROGRESS_INDICATOR
import net.mullvad.mullvadvpn.compose.test.CONNECT_BUTTON_TEST_TAG
import net.mullvad.mullvadvpn.compose.test.CONNECT_CARD_HEADER_TEST_TAG
import net.mullvad.mullvadvpn.compose.test.RECONNECT_BUTTON_TEST_TAG
import net.mullvad.mullvadvpn.compose.test.SELECT_LOCATION_BUTTON_TEST_TAG
import net.mullvad.mullvadvpn.compose.transitions.HomeTransition
import net.mullvad.mullvadvpn.compose.util.CollectSideEffectWithLifecycle
import net.mullvad.mullvadvpn.compose.util.OnNavResultValue
import net.mullvad.mullvadvpn.compose.util.RequestVpnPermission
import net.mullvad.mullvadvpn.compose.util.showSnackbarImmediately
import net.mullvad.mullvadvpn.constant.SECURE_ZOOM
import net.mullvad.mullvadvpn.constant.SECURE_ZOOM_ANIMATION_MILLIS
import net.mullvad.mullvadvpn.constant.UNSECURE_ZOOM
import net.mullvad.mullvadvpn.constant.fallbackLatLong
import net.mullvad.mullvadvpn.lib.map.AnimatedMap
import net.mullvad.mullvadvpn.lib.map.data.GlobeColors
import net.mullvad.mullvadvpn.lib.map.data.LocationMarkerColors
import net.mullvad.mullvadvpn.lib.map.data.Marker
import net.mullvad.mullvadvpn.lib.model.GeoIpLocation
import net.mullvad.mullvadvpn.lib.model.LatLong
import net.mullvad.mullvadvpn.lib.model.Latitude
import net.mullvad.mullvadvpn.lib.model.Longitude
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.theme.AppTheme
import net.mullvad.mullvadvpn.lib.theme.Dimens
import net.mullvad.mullvadvpn.lib.theme.Shapes
import net.mullvad.mullvadvpn.lib.theme.color.Alpha20
import net.mullvad.mullvadvpn.lib.theme.color.Alpha80
import net.mullvad.mullvadvpn.lib.theme.color.AlphaInvisible
import net.mullvad.mullvadvpn.lib.theme.color.AlphaScrollbar
import net.mullvad.mullvadvpn.lib.theme.color.AlphaVisible
import net.mullvad.mullvadvpn.lib.theme.typeface.connectionStatus
import net.mullvad.mullvadvpn.lib.theme.typeface.hostname
import net.mullvad.mullvadvpn.util.appendHideNavOnPlayBuild
import net.mullvad.mullvadvpn.util.removeHtmlTags
import net.mullvad.mullvadvpn.viewmodel.ConnectViewModel
import org.koin.androidx.compose.koinViewModel

private const val CONNECT_BUTTON_THROTTLE_MILLIS = 1000
private val SCREEN_HEIGHT_THRESHOLD = 700.dp
private const val SHORT_SCREEN_INDICATOR_BIAS = 0.2f
private const val TALL_SCREEN_INDICATOR_BIAS = 0.3f

@Preview("Initial|Connected|Disconnected|Connecting|Error.VpnPermissionDenied")
@Composable
private fun PreviewAccountScreen(
    @PreviewParameter(ConnectUiStatePreviewParameterProvider::class) state: ConnectUiState
) {
    AppTheme { ConnectScreen(state = state) }
}

@Destination<RootGraph>(style = HomeTransition::class)
@Composable
fun Connect(
    navigator: DestinationsNavigator,
    selectLocationResultRecipient: ResultRecipient<SelectLocationDestination, Boolean>,
) {
    val connectViewModel: ConnectViewModel = koinViewModel()

    val state by connectViewModel.uiState.collectAsStateWithLifecycle()

    val context = LocalContext.current

    val snackbarHostState = remember { SnackbarHostState() }

    val launchVpnPermission =
        rememberLauncherForActivityResult(RequestVpnPermission()) {
            connectViewModel.requestVpnPermissionResult(it)
        }

    val openAccountPage = LocalUriHandler.current.createOpenAccountPageHook()
    CollectSideEffectWithLifecycle(
        connectViewModel.uiSideEffect,
        minActiveState = Lifecycle.State.RESUMED,
    ) { sideEffect ->
        when (sideEffect) {
            is ConnectViewModel.UiSideEffect.OpenAccountManagementPageInBrowser -> {
                openAccountPage(sideEffect.token)
            }

            is ConnectViewModel.UiSideEffect.OutOfTime ->
                navigator.navigate(OutOfTimeDestination) {
                    launchSingleTop = true
                    popUpTo(NavGraphs.root) { inclusive = true }
                }

            ConnectViewModel.UiSideEffect.RevokedDevice ->
                navigator.navigate(DeviceRevokedDestination) {
                    launchSingleTop = true
                    popUpTo(NavGraphs.root) { inclusive = true }
                }

            is ConnectViewModel.UiSideEffect.NoVpnPermission -> launchVpnPermission.launch(Unit)
            is ConnectViewModel.UiSideEffect.ConnectError ->
                launch {
                    snackbarHostState.showSnackbarImmediately(
                        message = sideEffect.toMessage(context)
                    )
                }
        }
    }

    selectLocationResultRecipient.OnNavResultValue { result ->
        if (result) {
            connectViewModel.onConnectClick()
        }
    }

    ConnectScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onDisconnectClick = connectViewModel::onDisconnectClick,
        onReconnectClick = connectViewModel::onReconnectClick,
        onConnectClick = connectViewModel::onConnectClick,
        onCancelClick = connectViewModel::onCancelClick,
        onSwitchLocationClick = dropUnlessResumed { navigator.navigate(SelectLocationDestination) },
        onUpdateVersionClick = {
            val intent =
                Intent(
                        Intent.ACTION_VIEW,
                        Uri.parse(
                            context
                                .getString(R.string.download_url)
                                .appendHideNavOnPlayBuild(state.isPlayBuild)
                        ),
                    )
                    .apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK }
            context.startActivity(intent)
        },
        onManageAccountClick = connectViewModel::onManageAccountClick,
        onSettingsClick = dropUnlessResumed { navigator.navigate(SettingsDestination) },
        onAccountClick = dropUnlessResumed { navigator.navigate(AccountDestination) },
        onDismissNewDeviceClick = connectViewModel::dismissNewDeviceNotification,
    )
}

@Composable
fun ConnectScreen(
    state: ConnectUiState,
    snackbarHostState: SnackbarHostState = SnackbarHostState(),
    onDisconnectClick: () -> Unit = {},
    onReconnectClick: () -> Unit = {},
    onConnectClick: () -> Unit = {},
    onCancelClick: () -> Unit = {},
    onSwitchLocationClick: () -> Unit = {},
    onUpdateVersionClick: () -> Unit = {},
    onManageAccountClick: () -> Unit = {},
    onSettingsClick: () -> Unit = {},
    onAccountClick: () -> Unit = {},
    onDismissNewDeviceClick: () -> Unit = {},
) {

    ScaffoldWithTopBarAndDeviceName(
        topBarColor = state.tunnelState.topBarColor(),
        iconTintColor = state.tunnelState.iconTintColor(),
        onSettingsClicked = onSettingsClick,
        onAccountClicked = onAccountClick,
        deviceName = state.deviceName,
        timeLeft = state.daysLeftUntilExpiry,
        snackbarHostState = snackbarHostState,
    ) {
        val configuration = LocalConfiguration.current
        val screenHeight = configuration.screenHeightDp.dp
        val indicatorPercentOffset =
            if (screenHeight < SCREEN_HEIGHT_THRESHOLD) SHORT_SCREEN_INDICATOR_BIAS
            else TALL_SCREEN_INDICATOR_BIAS

        Box(Modifier.padding(it).fillMaxSize()) {
            MullvadMap(state, indicatorPercentOffset)

            MullvadCircularProgressIndicatorLarge(
                color = MaterialTheme.colorScheme.onSurface,
                modifier =
                    Modifier.layout { measurable, constraints ->
                            val placeable = measurable.measure(constraints)
                            layout(placeable.width, placeable.height) {
                                placeable.placeRelative(
                                    x = (constraints.maxWidth * 0.5f - placeable.width / 2).toInt(),
                                    y =
                                        (constraints.maxHeight * indicatorPercentOffset -
                                                placeable.height / 2)
                                            .toInt(),
                                )
                            }
                        }
                        .alpha(if (state.showLoading) AlphaVisible else AlphaInvisible)
                        .testTag(CIRCULAR_PROGRESS_INDICATOR),
            )

            NotificationBanner(
                notification = state.inAppNotification,
                isPlayBuild = state.isPlayBuild,
                onClickUpdateVersion = onUpdateVersionClick,
                onClickShowAccount = onManageAccountClick,
                onClickDismissNewDevice = onDismissNewDeviceClick,
            )
            ConnectionCard(
                state = state,
                modifier = Modifier.align(Alignment.BottomCenter),
                onSwitchLocationClick,
                onDisconnectClick,
                onReconnectClick,
                onCancelClick,
                onConnectClick,
            )
        }
    }
}

@Composable
private fun MullvadMap(state: ConnectUiState, progressIndicatorBias: Float) {

    // Distance to marker when secure/unsecure
    val baseZoom =
        animateFloatAsState(
            targetValue =
                if (state.tunnelState is TunnelState.Connected) SECURE_ZOOM else UNSECURE_ZOOM,
            animationSpec = tween(SECURE_ZOOM_ANIMATION_MILLIS),
            label = "baseZoom",
        )

    val markers = state.tunnelState.toMarker(state.location)?.let { listOf(it) } ?: emptyList()

    AnimatedMap(
        modifier = Modifier,
        cameraLocation = state.location?.toLatLong() ?: fallbackLatLong,
        cameraBaseZoom = baseZoom.value,
        cameraVerticalBias = progressIndicatorBias,
        markers = markers,
        globeColors =
            GlobeColors(
                landColor = MaterialTheme.colorScheme.primary,
                oceanColor = MaterialTheme.colorScheme.surface,
            ),
    )
}

@Composable
private fun ConnectionCard(
    state: ConnectUiState,
    modifier: Modifier = Modifier,
    onSwitchLocationClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onReconnectClick: () -> Unit,
    onCancelClick: () -> Unit,
    onConnectClick: () -> Unit,
) {
    var expanded by rememberSaveable(state.tunnelState::class) { mutableStateOf(false) }
    val containerColor =
        animateColorAsState(
            if (expanded) MaterialTheme.colorScheme.surfaceContainer
            else MaterialTheme.colorScheme.surfaceContainer.copy(alpha = Alpha80),
            label = "connection_card_color",
        )

    Card(
        modifier =
            modifier.widthIn(max = Dimens.connectionCardMaxWidth).padding(Dimens.mediumPadding),
        Shapes.large,
        colors = CardDefaults.cardColors(containerColor = containerColor.value),
    ) {
        Column(
            modifier =
                Modifier.padding(
                    top = Dimens.mediumPadding,
                    start = Dimens.mediumPadding,
                    end = Dimens.mediumPadding,
                    bottom = Dimens.smallPadding,
                )
        ) {
            ConnectionCardHeader(state, state.location, expanded) { expanded = !expanded }

            AnimatedContent(
                state.tunnelState as? TunnelState.Connected to expanded,
                modifier = Modifier.weight(1f, fill = false),
                label = "connection_card_connection_details",
            ) { (connectedState, isExpanded) ->
                if (connectedState != null) {
                    ConnectionInfo(
                        connectedState,
                        isExpanded,
                        onToggleExpand = { expanded = !expanded },
                    )
                } else {
                    Spacer(Modifier.height(Dimens.smallSpacer))
                }
            }

            Spacer(Modifier.height(Dimens.mediumPadding))

            ButtonPanel(
                state,
                onSwitchLocationClick,
                onDisconnectClick,
                onReconnectClick,
                onCancelClick,
                onConnectClick,
            )
        }
    }
}

@Composable
private fun ConnectionCardHeader(
    state: ConnectUiState,
    location: GeoIpLocation?,
    expanded: Boolean,
    onToggleExpand: () -> Unit,
) {
    Column(
        modifier =
            Modifier.fillMaxWidth()
                .clickable(
                    enabled = state.tunnelState is TunnelState.Connected,
                    onClick = onToggleExpand,
                )
                .testTag(CONNECT_CARD_HEADER_TEST_TAG)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            ConnectionStatusText(state = state.tunnelState)
            if (state.tunnelState is TunnelState.Connected) {
                ExpandChevron(isExpanded = !expanded, color = MaterialTheme.colorScheme.onSurface)
            }
        }

        Text(
            modifier = Modifier.fillMaxWidth().padding(top = Dimens.tinyPadding),
            text = location.asString(),
            style = MaterialTheme.typography.connectionStatus,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        val hostname =
            when {
                location?.entryHostname != null && location.hostname != null ->
                    stringResource(R.string.x_via_x, location.hostname!!, location.entryHostname!!)
                else -> location?.hostname
            }
        AnimatedContent(hostname, label = "hostname") {
            if (it != null) {
                Text(
                    modifier = Modifier.fillMaxWidth(),
                    text = it,
                    style = MaterialTheme.typography.hostname,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

private fun GeoIpLocation?.asString(): String {
    return if (this == null) ""
    else {
        buildString {
            append(country)
            city?.let {
                append(", ")
                append(it)
            }
        }
    }
}

@Composable
private fun ConnectionInfo(
    tunnelState: TunnelState.Connected,
    expanded: Boolean,
    onToggleExpand: () -> Unit,
) {
    val scrollState = rememberScrollState()
    Column {
        if (expanded) {
            HorizontalDivider(
                Modifier.padding(vertical = Dimens.smallPadding),
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(Alpha20),
            )
        }
        Column(
            modifier =
                Modifier.fillMaxWidth()
                    .drawVerticalScrollbar(
                        scrollState,
                        color = MaterialTheme.colorScheme.onPrimary.copy(alpha = AlphaScrollbar),
                    )
                    .verticalScroll(scrollState)
        ) {
            FeatureIndicatorsPanel(tunnelState.featureIndicators, expanded, onToggleExpand)

            if (expanded) {
                ConnectionDetailPanel(tunnelState)
            }
        }
    }
}

@Composable
private fun ButtonPanel(
    state: ConnectUiState,
    onSwitchLocationClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onReconnectClick: () -> Unit,
    onCancelClick: () -> Unit,
    onConnectClick: () -> Unit,
) {
    var lastConnectionActionTimestamp by remember { mutableLongStateOf(0L) }

    fun handleThrottledAction(action: () -> Unit) {
        val currentTime = System.currentTimeMillis()
        if ((currentTime - lastConnectionActionTimestamp) > CONNECT_BUTTON_THROTTLE_MILLIS) {
            lastConnectionActionTimestamp = currentTime
            action.invoke()
        }
    }
    Column(modifier = Modifier.padding(vertical = Dimens.tinyPadding)) {
        SwitchLocationButton(
            text =
                if (state.showLocation && state.selectedRelayItemTitle != null) {
                    state.selectedRelayItemTitle
                } else {
                    stringResource(id = R.string.switch_location)
                },
            onSwitchLocation = onSwitchLocationClick,
            reconnectClick = { handleThrottledAction(onReconnectClick) },
            isReconnectButtonEnabled =
                state.tunnelState is TunnelState.Connected ||
                    state.tunnelState is TunnelState.Connecting,
            modifier = Modifier.testTag(SELECT_LOCATION_BUTTON_TEST_TAG),
            reconnectButtonTestTag = RECONNECT_BUTTON_TEST_TAG,
        )
        Spacer(Modifier.height(Dimens.buttonVerticalPadding))

        ConnectionButton(
            modifier = Modifier.fillMaxWidth().testTag(CONNECT_BUTTON_TEST_TAG),
            state = state.tunnelState,
            disconnectClick = onDisconnectClick,
            cancelClick = onCancelClick,
            connectClick = { handleThrottledAction(onConnectClick) },
        )
    }
}

@Composable
fun TunnelState.toMarker(location: GeoIpLocation?): Marker? {
    if (location == null) return null
    return when (this) {
        is TunnelState.Connected ->
            Marker(
                location.toLatLong(),
                colors = LocationMarkerColors(centerColor = MaterialTheme.colorScheme.tertiary),
            )

        is TunnelState.Connecting -> null
        is TunnelState.Disconnected ->
            Marker(
                location.toLatLong(),
                colors = LocationMarkerColors(centerColor = MaterialTheme.colorScheme.error),
            )

        is TunnelState.Disconnecting -> null
        is TunnelState.Error -> null
    }
}

@Composable
fun TunnelState.topBarColor(): Color =
    if (isSecured()) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.error

@Composable
fun TunnelState.iconTintColor(): Color =
    if (isSecured()) {
        MaterialTheme.colorScheme.onTertiary
    } else {
        MaterialTheme.colorScheme.onError
    }

fun GeoIpLocation.toLatLong() =
    LatLong(Latitude(latitude.toFloat()), Longitude(longitude.toFloat()))

private fun ConnectViewModel.UiSideEffect.ConnectError.toMessage(context: Context): String =
    when (this) {
        ConnectViewModel.UiSideEffect.ConnectError.NoVpnPermission ->
            context.getString(R.string.vpn_permission_denied_error)

        is ConnectViewModel.UiSideEffect.ConnectError.AlwaysOnVpn ->
            // Snackbar currently do not support annotated string
            context
                .getString(R.string.always_on_vpn_error_notification_content, appName)
                .removeHtmlTags()

        ConnectViewModel.UiSideEffect.ConnectError.Generic ->
            context.getString(R.string.error_occurred)
    }
