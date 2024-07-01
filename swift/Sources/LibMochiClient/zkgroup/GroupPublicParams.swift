//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class GroupPublicParams: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: mochi_group_public_params_check_valid_contents)
    }

    public func getGroupIdentifier() throws -> GroupIdentifier {
        return try withUnsafePointerToSerialized { contents in
            try invokeFnReturningSerialized {
                mochi_group_public_params_get_group_identifier($0, contents)
            }
        }
    }
}
