//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class ServerSecretParams: NativeHandleOwner {
    public static func generate() throws -> ServerSecretParams {
        return try self.generate(randomness: Randomness.generate())
    }

    public static func generate(randomness: Randomness) throws -> ServerSecretParams {
        return try randomness.withUnsafePointerToBytes { randomness in
            try invokeFnReturningNativeHandle {
                mochi_server_secret_params_generate_deterministic($0, randomness)
            }
        }
    }

    public convenience init(contents: [UInt8]) throws {
        var handle: OpaquePointer?
        try contents.withUnsafeBorrowedBuffer {
            try checkError(mochi_server_secret_params_deserialize(&handle, $0))
        }
        self.init(owned: handle!)
    }

    required init(owned: OpaquePointer) {
        super.init(owned: owned)
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try withNativeHandle { handle in
                try invokeFnReturningArray {
                    mochi_server_secret_params_serialize($0, handle)
                }
            }
        }
    }

    public func getPublicParams() throws -> ServerPublicParams {
        return try withNativeHandle { contents in
            try invokeFnReturningNativeHandle {
                mochi_server_secret_params_get_public_params($0, contents)
            }
        }
    }

    public func sign(message: [UInt8]) throws -> NotarySignature {
        return try self.sign(randomness: Randomness.generate(), message: message)
    }

    public func sign(randomness: Randomness, message: [UInt8]) throws -> NotarySignature {
        return try withNativeHandle { contents in
            try randomness.withUnsafePointerToBytes { randomness in
                try message.withUnsafeBorrowedBuffer { message in
                    try invokeFnReturningSerialized {
                        mochi_server_secret_params_sign_deterministic($0, contents, randomness, message)
                    }
                }
            }
        }
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        mochi_server_secret_params_destroy(handle)
    }
}
