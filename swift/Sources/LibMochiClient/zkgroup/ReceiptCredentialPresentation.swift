//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class ReceiptCredentialPresentation: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: mochi_receipt_credential_presentation_check_valid_contents)
    }

    public func getReceiptExpirationTime() throws -> UInt64 {
        return try withUnsafePointerToSerialized { contents in
            try invokeFnReturningInteger {
                mochi_receipt_credential_presentation_get_receipt_expiration_time($0, contents)
            }
        }
    }

    public func getReceiptLevel() throws -> UInt64 {
        return try withUnsafePointerToSerialized { contents in
            try invokeFnReturningInteger {
                mochi_receipt_credential_presentation_get_receipt_level($0, contents)
            }
        }
    }

    public func getReceiptSerial() throws -> ReceiptSerial {
        return try withUnsafePointerToSerialized { contents in
            try invokeFnReturningSerialized {
                mochi_receipt_credential_presentation_get_receipt_serial($0, contents)
            }
        }
    }
}
