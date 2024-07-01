//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class GenericServerPublicParams: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: mochi_generic_server_public_params_check_valid_contents)
    }
}
