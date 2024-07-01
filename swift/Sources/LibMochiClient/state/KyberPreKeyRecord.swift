//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class KyberPreKeyRecord: ClonableHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_kyber_pre_key_record_destroy(handle)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_kyber_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(mochi_kyber_pre_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public convenience init<Bytes: ContiguousBytes>(
        id: UInt32,
        timestamp: UInt64,
        keyPair: KEMKeyPair,
        signature: Bytes
    ) throws {
        var result: OpaquePointer?
        try keyPair.withNativeHandle { keyPairHandle in
            try signature.withUnsafeBorrowedBuffer {
                try checkError(mochi_kyber_pre_key_record_new(&result, id, timestamp, keyPairHandle, $0))
            }
        }
        self.init(owned: result!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_kyber_pre_key_record_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var id: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_kyber_pre_key_record_get_id($0, nativeHandle)
                }
            }
        }
    }

    public var timestamp: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_kyber_pre_key_record_get_timestamp($0, nativeHandle)
                }
            }
        }
    }

    public var keyPair: KEMKeyPair {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_kyber_pre_key_record_get_key_pair($0, nativeHandle)
                }
            }
        }
    }

    public var publicKey: KEMPublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_kyber_pre_key_record_get_public_key($0, nativeHandle)
                }
            }
        }
    }

    public var secretKey: KEMSecretKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_kyber_pre_key_record_get_secret_key($0, nativeHandle)
                }
            }
        }
    }

    public var signature: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_kyber_pre_key_record_get_signature($0, nativeHandle)
                }
            }
        }
    }
}
