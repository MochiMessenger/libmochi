//
// Copyright 2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class ExpiringProfileKeyCredential: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: mochi_expiring_profile_key_credential_check_valid_contents)
    }

    public var expirationTime: Date {
        let timestampInSeconds = failOnError {
            try self.withUnsafePointerToSerialized { contents in
                try invokeFnReturningInteger {
                    mochi_expiring_profile_key_credential_get_expiration_time($0, contents)
                }
            }
        }
        return Date(timeIntervalSince1970: TimeInterval(timestampInSeconds))
    }
}
