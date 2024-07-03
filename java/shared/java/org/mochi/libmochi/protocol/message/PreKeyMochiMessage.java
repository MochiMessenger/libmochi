//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.message;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.Optional;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.IdentityKey;
import org.mochi.libmochi.protocol.InvalidKeyException;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.InvalidVersionException;
import org.mochi.libmochi.protocol.LegacyMessageException;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;

public class PreKeyMochiMessage implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.PreKeyMochiMessage_Destroy(this.unsafeHandle);
  }

  public PreKeyMochiMessage(byte[] serialized)
      throws InvalidMessageException,
          InvalidVersionException,
          LegacyMessageException,
          InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            LegacyMessageException.class,
            InvalidKeyException.class,
            () -> Native.PreKeyMochiMessage_Deserialize(serialized));
  }

  public PreKeyMochiMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public int getMessageVersion() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.PreKeyMochiMessage_GetVersion(guard.nativeHandle()));
    }
  }

  public IdentityKey getIdentityKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new IdentityKey(
          filterExceptions(() -> Native.PreKeyMochiMessage_GetIdentityKey(guard.nativeHandle())));
    }
  }

  public int getRegistrationId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.PreKeyMochiMessage_GetRegistrationId(guard.nativeHandle()));
    }
  }

  public Optional<Integer> getPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      int pre_key =
          filterExceptions(() -> Native.PreKeyMochiMessage_GetPreKeyId(guard.nativeHandle()));
      if (pre_key < 0) {
        return Optional.empty();
      } else {
        return Optional.of(pre_key);
      }
    }
  }

  public int getSignedPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.PreKeyMochiMessage_GetSignedPreKeyId(guard.nativeHandle()));
    }
  }

  public ECPublicKey getBaseKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.PreKeyMochiMessage_GetBaseKey(guard.nativeHandle()));
    }
  }

  public MochiMessage getWhisperMessage() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new MochiMessage(Native.PreKeyMochiMessage_GetMochiMessage(guard.nativeHandle()));
    }
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.PreKeyMochiMessage_GetSerialized(guard.nativeHandle()));
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.PREKEY_TYPE;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
