//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class ServerPublicParams: NativeHandleOwner {
    public convenience init(contents: [UInt8]) throws {
        var handle: OpaquePointer?
        try contents.withUnsafeBorrowedBuffer {
            try checkError(mochi_server_public_params_deserialize(&handle, $0))
        }
        self.init(owned: handle!)
    }

    required init(owned: OpaquePointer) {
        super.init(owned: owned)
    }

    public func verifySignature(message: [UInt8], notarySignature: NotarySignature) throws {
        try withNativeHandle { contents in
            try message.withUnsafeBorrowedBuffer { message in
                try notarySignature.withUnsafePointerToSerialized { notarySignature in
                    try checkError(mochi_server_public_params_verify_signature(contents, message, notarySignature))
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try withNativeHandle { handle in
                try invokeFnReturningArray {
                    mochi_server_public_params_serialize($0, handle)
                }
            }
        }
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        mochi_server_public_params_destroy(handle)
    }
}
