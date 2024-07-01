//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class PreKeyRecord: ClonableHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_pre_key_record_destroy(handle)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_pre_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(mochi_pre_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public convenience init(
        id: UInt32,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ) throws {
        var handle: OpaquePointer?
        try withNativeHandles(publicKey, privateKey) { publicKeyHandle, privateKeyHandle in
            try checkError(mochi_pre_key_record_new(&handle, id, publicKeyHandle, privateKeyHandle))
        }
        self.init(owned: handle!)
    }

    public convenience init(id: UInt32, privateKey: PrivateKey) throws {
        try self.init(id: id, publicKey: privateKey.publicKey, privateKey: privateKey)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_pre_key_record_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var id: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_pre_key_record_get_id($0, nativeHandle)
                }
            }
        }
    }

    public var publicKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_pre_key_record_get_public_key($0, nativeHandle)
                }
            }
        }
    }

    public var privateKey: PrivateKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_pre_key_record_get_private_key($0, nativeHandle)
                }
            }
        }
    }
}
