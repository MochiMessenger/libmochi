//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class PrivateKey: ClonableHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(mochi_privatekey_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public static func generate() -> PrivateKey {
        return failOnError {
            try invokeFnReturningNativeHandle {
                mochi_privatekey_generate($0)
            }
        }
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_privatekey_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_privatekey_destroy(handle)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_privatekey_serialize($0, nativeHandle)
                }
            }
        }
    }

    public func generateSignature<Bytes: ContiguousBytes>(message: Bytes) -> [UInt8] {
        return withNativeHandle { nativeHandle in
            message.withUnsafeBorrowedBuffer { messageBuffer in
                failOnError {
                    try invokeFnReturningArray {
                        mochi_privatekey_sign($0, nativeHandle, messageBuffer)
                    }
                }
            }
        }
    }

    public func keyAgreement(with other: PublicKey) -> [UInt8] {
        return withNativeHandles(self, other) { nativeHandle, otherHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_privatekey_agree($0, nativeHandle, otherHandle)
                }
            }
        }
    }

    public var publicKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_privatekey_get_public_key($0, nativeHandle)
                }
            }
        }
    }
}
