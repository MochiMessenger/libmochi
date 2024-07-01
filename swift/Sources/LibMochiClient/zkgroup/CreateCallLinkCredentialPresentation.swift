//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public class CreateCallLinkCredentialPresentation: ByteArray {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: mochi_create_call_link_credential_presentation_check_valid_contents)
    }

    public func verify<RoomId: ContiguousBytes>(roomId: RoomId, now: Date = Date(), serverParams: GenericServerSecretParams, callLinkParams: CallLinkPublicParams) throws {
        try withUnsafeBorrowedBuffer { contents in
            try roomId.withUnsafeBorrowedBuffer { roomId in
                try serverParams.withUnsafeBorrowedBuffer { serverParams in
                    try callLinkParams.withUnsafeBorrowedBuffer { callLinkParams in
                        try checkError(mochi_create_call_link_credential_presentation_verify(contents, roomId, UInt64(now.timeIntervalSince1970), serverParams, callLinkParams))
                    }
                }
            }
        }
    }
}
