//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import MochiFfi

public struct Randomness {
    public var bytes: MochiRandomnessBytes

    public init(_ bytes: MochiRandomnessBytes) {
        self.bytes = bytes
    }

    static func generate() throws -> Randomness {
        var bytes: MochiRandomnessBytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        try withUnsafeMutableBytes(of: &bytes) {
            try fillRandom($0)
        }
        return Randomness(bytes)
    }

    func withUnsafePointerToBytes<Result>(_ callback: (UnsafePointer<MochiRandomnessBytes>) throws -> Result) rethrows -> Result {
        try withUnsafePointer(to: self.bytes, callback)
    }
}
