//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class SenderKeyRecord: ClonableHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_sender_key_record_destroy(handle)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_sender_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(mochi_sender_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_sender_key_record_serialize($0, nativeHandle)
                }
            }
        }
    }
}
