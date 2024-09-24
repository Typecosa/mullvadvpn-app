//
//  EncryptedDNSProxy.swift
//  MullvadRustRuntime
//
//  Created by Emils on 24/09/2024.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadRustRuntimeProxy

enum EncryptedDnsProxyError: Error {
    case initialization
    case start(err: Int32)
}

public class EncryptedDNSProxy {
    private var proxyConfig: ProxyHandle
    private var stateLock = NSLock()
    private var didStart = false
    private let state: OpaquePointer

    public init() {
        state = encrypted_dns_proxy_init()
        proxyConfig = ProxyHandle(context: nil, port: 0)
    }

    public func localPort() -> UInt16 {
        stateLock.lock()
        defer { stateLock.unlock() }
        return proxyConfig.port
    }

    public func start() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard didStart == false else { return }
        didStart = true

        let err = encrypted_dns_proxy_start(state, &proxyConfig)
        if err != 0 {
            throw EncryptedDnsProxyError.start(err: err)
        }
    }

    public func stop() {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard didStart == true else { return }
        didStart = false

        encrypted_dns_proxy_stop(&proxyConfig)
    }

    deinit {
        if didStart {
            encrypted_dns_proxy_stop(&proxyConfig)
        }

        encrytped_dns_proxy_free(state)
    }
}
