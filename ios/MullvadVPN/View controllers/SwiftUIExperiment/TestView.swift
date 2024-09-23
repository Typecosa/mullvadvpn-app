//
//  TestView.swift
//  MullvadVPN
//
//  Created by Andrew Bulhak on 2024-09-23.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import SwiftUI

struct TestView: View {
    var body: some View {
        VStack {
            // TODO: the image goes here
//            AsyncImage(url: URL(string: "https://placekitten.com/600/300")).aspectRatio(2, contentMode: .fill)
            Text(
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.\n\nCan only be used with Wireguard"
            )
            .padding(EdgeInsets(UIMetrics.contentLayoutMargins))

            HStack {
                Toggle(isOn: /*@START_MENU_TOKEN@*/ .constant(true)/*@END_MENU_TOKEN@*/, label: {
                    Text("Enable")
                }).accessibilityIdentifier(AccessibilityIdentifier.multihopSwitch.rawValue)
            }.padding(EdgeInsets(UIMetrics.SettingsCell.layoutMargins))
                .background(Color(UIColor.primaryColor))
            Spacer()
        }
        .background(Color(UIColor.secondaryColor))
        .foregroundColor(Color(UIColor.primaryTextColor))
        .navigationTitle("Multihop")
    }
}

#Preview {
    TestView()
}
