#include "stdafx.h"
#include "blockall.h"
#include <winfw/mullvadguids.h>
#include <libwfp/filterbuilder.h>
#include <libwfp/nullconditionbuilder.h>
#include <libwfp/conditionbuilder.h>
#include <libwfp/conditions/conditionl2flags.h>>
#include <libwfp/conditions/conditioninterface.h>
#include <fwpmu.h>
#include <memory>
#include <iphlpapi.h>

namespace rules::baseline
{

bool BlockAll::apply(IObjectInstaller &objectInstaller)
{
	wfp::FilterBuilder filterBuilder;

	//
	// #1 Block outbound connections, IPv4.
	//

	filterBuilder
		.key(MullvadGuids::Filter_Baseline_BlockAll_Outbound_Ipv4())
		.name(L"Block all outbound connections (IPv4)")
		.description(L"This filter is part of a rule that restricts inbound and outbound traffic")
		.provider(MullvadGuids::Provider())
		.layer(FWPM_LAYER_ALE_AUTH_CONNECT_V4)
		.sublayer(MullvadGuids::SublayerBaseline())
		.weight(wfp::FilterBuilder::WeightClass::Min)
		.block();

	wfp::NullConditionBuilder nullConditionBuilder;

	if (false == objectInstaller.addFilter(filterBuilder, nullConditionBuilder))
	{
		return false;
	}

	//
	// #2 Block inbound connections, IPv4.
	//

	filterBuilder
		.key(MullvadGuids::Filter_Baseline_BlockAll_Inbound_Ipv4())
		.name(L"Block all inbound connections (IPv4)")
		.layer(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);

	if (false == objectInstaller.addFilter(filterBuilder, nullConditionBuilder))
	{
		return false;
	}

	//
	// #3 Block outbound connections, IPv6.
	//

	filterBuilder
		.key(MullvadGuids::Filter_Baseline_BlockAll_Outbound_Ipv6())
		.name(L"Block all outbound connections (IPv6)")
		.layer(FWPM_LAYER_ALE_AUTH_CONNECT_V6);

	if (false == objectInstaller.addFilter(filterBuilder, nullConditionBuilder))
	{
		return false;
	}

	//
	// #4 Block inbound connections, IPv6.
	//

	filterBuilder
		.key(MullvadGuids::Filter_Baseline_BlockAll_Inbound_Ipv6())
		.name(L"Block all inbound connections (IPv6)")
		.layer(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);



	if (false == objectInstaller.addFilter(filterBuilder, nullConditionBuilder))
	{
		return false;
	}


	wfp::FilterBuilder filterBuilder2;
	wfp::ConditionBuilder conditionBuilder(FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE);
	auto index = if_nametoindex("Mullvad");
    conditionBuilder.add_condition(wfp::conditions::ConditionInterface::Index(index, wfp::conditions::CompareNeq()));
	conditionBuilder.add_condition(std::make_unique<wfp::conditions::ConditionL2Flags>());

	filterBuilder2
		.key(MullvadGuids::blabla())
		.name(L"Block all outbound Hyper-V traffic")
		.description(L"This filter is part of a rule that blocks traffic from WSL")
		.provider(MullvadGuids::Provider())
		.layer(FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE)
		.sublayer(MullvadGuids::SublayerBaseline())
		.weight(wfp::FilterBuilder::WeightClass::Min)
		.block();

	return objectInstaller.addFilter(filterBuilder2, conditionBuilder);
}

}
