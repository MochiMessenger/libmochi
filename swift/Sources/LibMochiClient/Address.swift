//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import MochiFfi

public class ProtocolAddress: ClonableHandleOwner {
    public convenience init(name: String, deviceId: UInt32) throws {
        var handle: OpaquePointer?
        try checkError(mochi_address_new(
            &handle,
            name,
            deviceId
        ))
        self.init(owned: handle!)
    }

    /// Creates a ProtocolAddress using the **uppercase** string representation of a service ID, for backward compatibility.
    public convenience init(_ serviceId: ServiceId, deviceId: UInt32) {
        do {
            try self.init(name: serviceId.serviceIdUppercaseString, deviceId: deviceId)
        } catch {
            // `self.init` can't be put inside a closure, but we want the same error handling `failOnError` gives us.
            // So we rethrow the error here.
            failOnError { () -> Never in throw error }
        }
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_address_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_address_destroy(handle)
    }

    public var name: String {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningString {
                    mochi_address_get_name($0, nativeHandle)
                }
            }
        }
    }

    /// Returns a ServiceId if this address contains a valid ServiceId, `nil` otherwise.
    ///
    /// In a future release ProtocolAddresses will *only* support ServiceIds.
    public var serviceId: ServiceId! {
        return try? ServiceId.parseFrom(serviceIdString: self.name)
    }

    public var deviceId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_address_get_device_id($0, nativeHandle)
                }
            }
        }
    }
}

extension ProtocolAddress: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "\(self.name).\(self.deviceId)"
    }
}

extension ProtocolAddress: Hashable {
    public static func == (lhs: ProtocolAddress, rhs: ProtocolAddress) -> Bool {
        if lhs.deviceId != rhs.deviceId {
            return false
        }

        return lhs.name == rhs.name
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.name)
        hasher.combine(self.deviceId)
    }
}
