//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public enum Ias {
    public static func verify<
        Signature: ContiguousBytes,
        Body: ContiguousBytes,
        CertPem: ContiguousBytes
    >(
        signature: Signature, of body: Body, withCertificatesPem certPem: CertPem, at timestamp: Date
    ) -> Bool {
        return failOnError {
            try signature.withUnsafeBorrowedBuffer { signatureBuffer in
                try body.withUnsafeBorrowedBuffer { bodyBuffer in
                    try certPem.withUnsafeBorrowedBuffer { pemBuffer in
                        try invokeFnReturningBool {
                            let timeMillis = UInt64(timestamp.timeIntervalSince1970 * 1000)
                            return mochi_verify_signature($0, pemBuffer, bodyBuffer, signatureBuffer, timeMillis)
                        }
                    }
                }
            }
        }
    }
}
