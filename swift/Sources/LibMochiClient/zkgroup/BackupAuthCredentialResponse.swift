//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class BackupAuthCredentialResponse: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: mochi_backup_auth_credential_response_check_valid_contents)
    }
}
