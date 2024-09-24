//
//  EncryptedDNSTransport.swift
//  MullvadVPN
//
//  Created by Mojgan on 2024-09-19.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//
import Foundation
import MullvadRustRuntime
import MullvadTypes

public final class EncryptedDNSTransport: RESTTransport {
    public var name: String {
        "encrypted-dns-url-session"
    }

    /// The `URLSession` used to send requests via `encryptedDNSProxy`
    public let urlSession: URLSession
    private let encryptedDnsProxy: EncryptedDNSProxy

    public init(
        urlSession: URLSession,
        addressCache: REST.AddressCache
    ) {
        self.urlSession = urlSession
        self.encryptedDnsProxy = EncryptedDNSProxy()
    }

    public func sendRequest(
        _ request: URLRequest,
        completion: @escaping (Data?, URLResponse?, (any Error)?) -> Void
    ) -> any Cancellable {
        // TODO: Handle this error
        do {
          try self.encryptedDnsProxy.start()
        } catch {
            return AnyCancellable {
                completion(nil, nil, error)
            }
        }
        

        var urlRequestCopy = request
        urlRequestCopy.url = request.url.flatMap { url in
            var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            components?.host = "127.0.0.1"
            components?.port = Int(encryptedDnsProxy.localPort())
            return components?.url
        }

        let wrappedCompletionHandler: (Data?, URLResponse?, (any Error)?)
            -> Void = { [weak self] data, response, maybeError in
                if maybeError != nil {
                    self?.encryptedDnsProxy.stop()
                }
                completion(data, response, maybeError)
            }

        let dataTask = urlSession.dataTask(with: urlRequestCopy, completionHandler: wrappedCompletionHandler)
        dataTask.resume()
        return dataTask
    }
}
