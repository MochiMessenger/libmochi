//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class KEMKeyPair: ClonableHandleOwner {
    public static func generate() -> KEMKeyPair {
        return failOnError {
            try invokeFnReturningNativeHandle {
                mochi_kyber_key_pair_generate($0)
            }
        }
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_kyber_key_pair_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_kyber_key_pair_destroy(handle)
    }

    public var publicKey: KEMPublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_kyber_key_pair_get_public_key($0, nativeHandle)
                }
            }
        }
    }

    public var secretKey: KEMSecretKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_kyber_key_pair_get_secret_key($0, nativeHandle)
                }
            }
        }
    }
}

public class KEMPublicKey: ClonableHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(mochi_kyber_public_key_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_kyber_public_key_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_kyber_public_key_destroy(handle)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_kyber_public_key_serialize($0, nativeHandle)
                }
            }
        }
    }
}

extension KEMPublicKey: Equatable {
    public static func == (lhs: KEMPublicKey, rhs: KEMPublicKey) -> Bool {
        return withNativeHandles(lhs, rhs) { lHandle, rHandle in
            failOnError {
                try invokeFnReturningBool {
                    mochi_kyber_public_key_equals($0, lHandle, rHandle)
                }
            }
        }
    }
}

public class KEMSecretKey: ClonableHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(mochi_kyber_secret_key_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_kyber_secret_key_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_kyber_secret_key_destroy(handle)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_kyber_secret_key_serialize($0, nativeHandle)
                }
            }
        }
    }
}
