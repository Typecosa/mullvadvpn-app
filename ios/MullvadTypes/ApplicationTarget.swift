//
//  ApplicationTarget.swift
//  MullvadVPN
//
//  Created by pronebird on 09/06/2023.
//  Copyright © 2023 Mullvad VPN AB. All rights reserved.
//

import Foundation

public enum ApplicationTarget: CaseIterable {
    case mainApp, packetTunnel

    /// Returns target bundle identifier.
    public var bundleIdentifier: String {
        let mainBundleIdentifier = Bundle.main.object(forInfoDictionaryKey: "MainApplicationIdentifier") as! String
        switch self {
        case .mainApp:
            return mainBundleIdentifier
        case .packetTunnel:
            return "\(mainBundleIdentifier).PacketTunnel"
        }
    }
}
