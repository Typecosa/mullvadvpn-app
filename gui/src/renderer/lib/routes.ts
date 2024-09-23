export enum RoutePath {
  launch = '/',
  login = '/login',
  tooManyDevices = '/login/too-many-devices',
  deviceRevoked = '/login/device-revoked',
  main = '/main',
  redeemVoucher = '/main/voucher/redeem',
  voucherSuccess = '/main/voucher/success/:newExpiry/:secondsAdded',
  expired = '/main/expired',
  timeAdded = '/main/time-added',
  setupFinished = '/main/setup-finished',
  settings = '/settings',
  selectLanguage = '/settings/language',
  account = '/account',
  general = '/settings/general',
  multihopSettings = '/settings/multihop',
  vpnSettings = '/settings/vpn',
  wireguardSettings = '/settings/advanced/wireguard',
  daitaSettings = '/settings/daita',
  udpOverTcp = '/settings/advanced/wireguard/udp-over-tcp',
  shadowsocks = '/settings/advanced/shadowsocks',
  openVpnSettings = '/settings/advanced/openvpn',
  splitTunneling = '/settings/split-tunneling',
  apiAccessMethods = '/settings/api-access-methods',
  settingsImport = '/settings/settings-import',
  settingsTextImport = '/settings/settings-import/text-import',
  editApiAccessMethods = '/settings/api-access-methods/edit/:id?',
  support = '/settings/support',
  problemReport = '/settings/support/problem-report',
  debug = '/settings/debug',
  selectLocation = '/select-location',
  editCustomBridge = '/select-location/edit-custom-bridge',
  filter = '/select-location/filter',
}
