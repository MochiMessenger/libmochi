//
// Copyright 2013-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.ecc;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidKeyException;

public class ECPrivateKey implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  static ECPrivateKey generate() {
    return new ECPrivateKey(Native.ECPrivateKey_Generate());
  }

  public ECPrivateKey(byte[] privateKey) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class, () -> Native.ECPrivateKey_Deserialize(privateKey));
  }

  public ECPrivateKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.ECPrivateKey_Destroy(this.unsafeHandle);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ECPrivateKey_Serialize(guard.nativeHandle()));
    }
  }

  public byte[] calculateSignature(byte[] message) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ECPrivateKey_Sign(guard.nativeHandle(), message));
    }
  }

  public byte[] calculateAgreement(ECPublicKey other) {
    try (NativeHandleGuard privateKey = new NativeHandleGuard(this);
        NativeHandleGuard publicKey = new NativeHandleGuard(other); ) {
      return filterExceptions(
          () -> Native.ECPrivateKey_Agree(privateKey.nativeHandle(), publicKey.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public ECPublicKey publicKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(
          filterExceptions(() -> Native.ECPrivateKey_GetPublicKey(guard.nativeHandle())));
    }
  }
}
