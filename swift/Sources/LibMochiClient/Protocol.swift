//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public func mochiEncrypt<Bytes: ContiguousBytes>(
    message: Bytes,
    for address: ProtocolAddress,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    now: Date = Date(),
    context: StoreContext
) throws -> CiphertextMessage {
    return try address.withNativeHandle { addressHandle in
        try message.withUnsafeBorrowedBuffer { messageBuffer in
            try withSessionStore(sessionStore, context) { ffiSessionStore in
                try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                    try invokeFnReturningNativeHandle {
                        mochi_encrypt_message($0, messageBuffer, addressHandle, ffiSessionStore, ffiIdentityStore, UInt64(now.timeIntervalSince1970 * 1000))
                    }
                }
            }
        }
    }
}

public func mochiDecrypt(
    message: MochiMessage,
    from address: ProtocolAddress,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    context: StoreContext
) throws -> [UInt8] {
    return try withNativeHandles(message, address) { messageHandle, addressHandle in
        try withSessionStore(sessionStore, context) { ffiSessionStore in
            try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                try invokeFnReturningArray {
                    mochi_decrypt_message($0, messageHandle, addressHandle, ffiSessionStore, ffiIdentityStore)
                }
            }
        }
    }
}

public func mochiDecryptPreKey(
    message: PreKeyMochiMessage,
    from address: ProtocolAddress,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    preKeyStore: PreKeyStore,
    signedPreKeyStore: SignedPreKeyStore,
    kyberPreKeyStore: KyberPreKeyStore,
    context: StoreContext
) throws -> [UInt8] {
    return try withNativeHandles(message, address) { messageHandle, addressHandle in
        try withSessionStore(sessionStore, context) { ffiSessionStore in
            try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                try withPreKeyStore(preKeyStore, context) { ffiPreKeyStore in
                    try withSignedPreKeyStore(signedPreKeyStore, context) { ffiSignedPreKeyStore in
                        try withKyberPreKeyStore(kyberPreKeyStore, context) { ffiKyberPreKeyStore in
                            try invokeFnReturningArray {
                                mochi_decrypt_pre_key_message($0, messageHandle, addressHandle, ffiSessionStore, ffiIdentityStore, ffiPreKeyStore, ffiSignedPreKeyStore, ffiKyberPreKeyStore)
                            }
                        }
                    }
                }
            }
        }
    }
}

public func processPreKeyBundle(
    _ bundle: PreKeyBundle,
    for address: ProtocolAddress,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    now: Date = Date(),
    context: StoreContext
) throws {
    return try withNativeHandles(bundle, address) { bundleHandle, addressHandle in
        try withSessionStore(sessionStore, context) { ffiSessionStore in
            try withIdentityKeyStore(identityStore, context) { ffiIdentityStore in
                try checkError(mochi_process_prekey_bundle(bundleHandle, addressHandle, ffiSessionStore, ffiIdentityStore, UInt64(now.timeIntervalSince1970 * 1000)))
            }
        }
    }
}

public func groupEncrypt<Bytes: ContiguousBytes>(
    _ message: Bytes,
    from sender: ProtocolAddress,
    distributionId: UUID,
    store: SenderKeyStore,
    context: StoreContext
) throws -> CiphertextMessage {
    return try sender.withNativeHandle { senderHandle in
        try message.withUnsafeBorrowedBuffer { messageBuffer in
            try withUnsafePointer(to: distributionId.uuid) { distributionId in
                try withSenderKeyStore(store, context) { ffiStore in
                    try invokeFnReturningNativeHandle {
                        mochi_group_encrypt_message($0, senderHandle, distributionId, messageBuffer, ffiStore)
                    }
                }
            }
        }
    }
}

public func groupDecrypt<Bytes: ContiguousBytes>(
    _ message: Bytes,
    from sender: ProtocolAddress,
    store: SenderKeyStore,
    context: StoreContext
) throws -> [UInt8] {
    return try sender.withNativeHandle { senderHandle in
        try message.withUnsafeBorrowedBuffer { messageBuffer in
            try withSenderKeyStore(store, context) { ffiStore in
                try invokeFnReturningArray {
                    mochi_group_decrypt_message($0, senderHandle, messageBuffer, ffiStore)
                }
            }
        }
    }
}

public func processSenderKeyDistributionMessage(
    _ message: SenderKeyDistributionMessage,
    from sender: ProtocolAddress,
    store: SenderKeyStore,
    context: StoreContext
) throws {
    return try withNativeHandles(sender, message) { senderHandle, messageHandle in
        try withSenderKeyStore(store, context) {
            try checkError(mochi_process_sender_key_distribution_message(
                senderHandle,
                messageHandle,
                $0
            ))
        }
    }
}
