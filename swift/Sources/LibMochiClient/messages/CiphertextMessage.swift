//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import MochiFfi

public class CiphertextMessage: NativeHandleOwner {
    public struct MessageType: RawRepresentable, Hashable {
        public var rawValue: UInt8
        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        internal init(_ knownType: MochiCiphertextMessageType) {
            self.init(rawValue: UInt8(knownType.rawValue))
        }

        public static var whisper: Self {
            return Self(MochiCiphertextMessageTypeWhisper)
        }

        public static var preKey: Self {
            return Self(MochiCiphertextMessageTypePreKey)
        }

        public static var senderKey: Self {
            return Self(MochiCiphertextMessageTypeSenderKey)
        }

        public static var plaintext: Self {
            return Self(MochiCiphertextMessageTypePlaintext)
        }
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_ciphertext_message_destroy(handle)
    }

    public convenience init(_ plaintextContent: PlaintextContent) {
        var result: OpaquePointer?
        plaintextContent.withNativeHandle { plaintextContentHandle in
            failOnError(mochi_ciphertext_message_from_plaintext_content(&result, plaintextContentHandle))
        }
        self.init(owned: result!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    mochi_ciphertext_message_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var messageType: MessageType {
        let rawValue = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_ciphertext_message_type($0, nativeHandle)
                }
            }
        }
        return MessageType(rawValue: rawValue)
    }
}
