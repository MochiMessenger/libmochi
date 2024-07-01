//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.message;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import javax.crypto.spec.SecretKeySpec;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.IdentityKey;
import org.mochi.libmochi.protocol.InvalidKeyException;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.InvalidVersionException;
import org.mochi.libmochi.protocol.LegacyMessageException;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;
import org.mochi.libmochi.protocol.util.ByteUtil;

public class MochiMessage implements CiphertextMessage, NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.MochiMessage_Destroy(this.unsafeHandle);
  }

  public MochiMessage(byte[] serialized)
      throws InvalidMessageException,
          InvalidVersionException,
          InvalidKeyException,
          LegacyMessageException {
    unsafeHandle =
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            InvalidKeyException.class,
            LegacyMessageException.class,
            () -> Native.MochiMessage_Deserialize(serialized));
  }

  public MochiMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public ECPublicKey getSenderRatchetKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(
          filterExceptions(() -> Native.MochiMessage_GetSenderRatchetKey(guard.nativeHandle())));
    }
  }

  public int getMessageVersion() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.MochiMessage_GetMessageVersion(guard.nativeHandle()));
    }
  }

  public int getCounter() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.MochiMessage_GetCounter(guard.nativeHandle()));
    }
  }

  public byte[] getBody() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.MochiMessage_GetBody(guard.nativeHandle()));
    }
  }

  public void verifyMac(
      IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)
      throws InvalidMessageException, InvalidKeyException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this);
        NativeHandleGuard senderIdentityGuard =
            new NativeHandleGuard(senderIdentityKey.getPublicKey());
        NativeHandleGuard receiverIdentityGuard =
            new NativeHandleGuard(receiverIdentityKey.getPublicKey()); ) {
      if (!filterExceptions(
          InvalidMessageException.class,
          InvalidKeyException.class,
          () ->
              Native.MochiMessage_VerifyMac(
                  guard.nativeHandle(),
                  senderIdentityGuard.nativeHandle(),
                  receiverIdentityGuard.nativeHandle(),
                  macKey.getEncoded()))) {
        throw new InvalidMessageException("Bad Mac!");
      }
    }
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.MochiMessage_GetSerialized(guard.nativeHandle()));
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.WHISPER_TYPE;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public static boolean isLegacy(byte[] message) {
    return message != null
        && message.length >= 1
        && ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
  }
}
