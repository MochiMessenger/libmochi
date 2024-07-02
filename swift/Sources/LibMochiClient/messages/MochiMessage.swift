//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class MochiMessage: NativeHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_message_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(mochi_message_deserialize(&result, $0))
        }
        self.init(owned: result!)
    }

    public var senderRatchetKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    mochi_message_get_sender_ratchet_key($0, nativeHandle)
                }
            }
        }
    }

    public var body: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_message_get_body($0, nativeHandle)
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_message_get_serialized($0, nativeHandle)
                }
            }
        }
    }

    public var messageVersion: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_message_get_message_version($0, nativeHandle)
                }
            }
        }
    }

    public var counter: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_message_get_counter($0, nativeHandle)
                }
            }
        }
    }

    public func verifyMac<Bytes: ContiguousBytes>(
        sender: PublicKey,
        receiver: PublicKey,
        macKey: Bytes
    ) throws -> Bool {
        return try withNativeHandles(self, sender, receiver) { messageHandle, senderHandle, receiverHandle in
            try macKey.withUnsafeBorrowedBuffer {
                var result = false
                try checkError(mochi_message_verify_mac(
                    &result,
                    messageHandle,
                    senderHandle,
                    receiverHandle,
                    $0
                ))
                return result
            }
        }
    }
}
