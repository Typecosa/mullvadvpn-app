import { Route, Switch } from 'react-router';

import LoginPage from '../components/Login';
import SelectLocation from '../components/select-location/SelectLocationContainer';
import { RoutePath } from '../lib/routes';
import { useViewTransitions } from '../lib/transition-hooks';
import Account from './Account';
import ApiAccessMethods from './ApiAccessMethods';
import DaitaSettings from './DaitaSettings';
import Debug from './Debug';
import { DeviceRevokedView } from './DeviceRevokedView';
import { EditApiAccessMethod } from './EditApiAccessMethod';
import { EditCustomBridge } from './EditCustomBridge';
import {
  SetupFinished,
  TimeAdded,
  VoucherInput,
  VoucherVerificationSuccess,
} from './ExpiredAccountAddTime';
import ExpiredAccountErrorView from './ExpiredAccountErrorView';
import Filter from './Filter';
import Launch from './Launch';
import MainView from './main-view/MainView';
import OpenVpnSettings from './OpenVpnSettings';
import ProblemReport from './ProblemReport';
import SelectLanguage from './SelectLanguage';
import Settings from './Settings';
import SettingsImport from './SettingsImport';
import SettingsTextImport from './SettingsTextImport';
import Shadowsocks from './Shadowsocks';
import SplitTunnelingSettings from './SplitTunnelingSettings';
import Support from './Support';
import TooManyDevices from './TooManyDevices';
import UdpOverTcp from './UdpOverTcp';
import UserInterfaceSettings from './UserInterfaceSettings';
import VpnSettings from './VpnSettings';
import WireguardSettings from './WireguardSettings';

export default function AppRouter() {
  const currentLocation = useViewTransitions();

  return (
    <Switch key={currentLocation.key} location={currentLocation}>
      <Route exact path={RoutePath.launch} component={Launch} />
      <Route exact path={RoutePath.login} component={LoginPage} />
      <Route exact path={RoutePath.tooManyDevices} component={TooManyDevices} />
      <Route exact path={RoutePath.deviceRevoked} component={DeviceRevokedView} />
      <Route exact path={RoutePath.main} component={MainView} />
      <Route exact path={RoutePath.expired} component={ExpiredAccountErrorView} />
      <Route exact path={RoutePath.redeemVoucher} component={VoucherInput} />
      <Route exact path={RoutePath.voucherSuccess} component={VoucherVerificationSuccess} />
      <Route exact path={RoutePath.timeAdded} component={TimeAdded} />
      <Route exact path={RoutePath.setupFinished} component={SetupFinished} />
      <Route exact path={RoutePath.account} component={Account} />
      <Route exact path={RoutePath.settings} component={Settings} />
      <Route exact path={RoutePath.selectLanguage} component={SelectLanguage} />
      <Route exact path={RoutePath.userInterfaceSettings} component={UserInterfaceSettings} />
      <Route exact path={RoutePath.vpnSettings} component={VpnSettings} />
      <Route exact path={RoutePath.wireguardSettings} component={WireguardSettings} />
      <Route exact path={RoutePath.daitaSettings} component={DaitaSettings} />
      <Route exact path={RoutePath.udpOverTcp} component={UdpOverTcp} />
      <Route exact path={RoutePath.shadowsocks} component={Shadowsocks} />
      <Route exact path={RoutePath.openVpnSettings} component={OpenVpnSettings} />
      <Route exact path={RoutePath.splitTunneling} component={SplitTunnelingSettings} />
      <Route exact path={RoutePath.apiAccessMethods} component={ApiAccessMethods} />
      <Route exact path={RoutePath.settingsImport} component={SettingsImport} />
      <Route exact path={RoutePath.settingsTextImport} component={SettingsTextImport} />
      <Route exact path={RoutePath.editApiAccessMethods} component={EditApiAccessMethod} />
      <Route exact path={RoutePath.support} component={Support} />
      <Route exact path={RoutePath.problemReport} component={ProblemReport} />
      <Route exact path={RoutePath.debug} component={Debug} />
      <Route exact path={RoutePath.selectLocation} component={SelectLocation} />
      <Route exact path={RoutePath.editCustomBridge} component={EditCustomBridge} />
      <Route exact path={RoutePath.filter} component={Filter} />
    </Switch>
  );
}
