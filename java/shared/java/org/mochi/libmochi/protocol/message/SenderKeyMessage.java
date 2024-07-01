//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.message;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.UUID;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.InvalidVersionException;
import org.mochi.libmochi.protocol.LegacyMessageException;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;

public class SenderKeyMessage implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.SenderKeyMessage_Destroy(this.unsafeHandle);
  }

  public SenderKeyMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  public SenderKeyMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException, LegacyMessageException {
    unsafeHandle =
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            LegacyMessageException.class,
            () -> Native.SenderKeyMessage_Deserialize(serialized));
  }

  public UUID getDistributionId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.SenderKeyMessage_GetDistributionId(guard.nativeHandle()));
    }
  }

  public int getChainId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderKeyMessage_GetChainId(guard.nativeHandle()));
    }
  }

  public int getIteration() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderKeyMessage_GetIteration(guard.nativeHandle()));
    }
  }

  public byte[] getCipherText() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderKeyMessage_GetCipherText(guard.nativeHandle()));
    }
  }

  public void verifySignature(ECPublicKey signatureKey) throws InvalidMessageException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this);
        NativeHandleGuard keyGuard = new NativeHandleGuard(signatureKey); ) {
      if (!filterExceptions(
          InvalidMessageException.class,
          () ->
              Native.SenderKeyMessage_VerifySignature(
                  guard.nativeHandle(), keyGuard.nativeHandle()))) {
        throw new InvalidMessageException("Invalid signature!");
      }
    }
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderKeyMessage_GetSerialized(guard.nativeHandle()));
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.SENDERKEY_TYPE;
  }
}
