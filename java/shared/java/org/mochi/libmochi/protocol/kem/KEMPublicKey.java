//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.kem;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.Arrays;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidKeyException;

public class KEMPublicKey implements NativeHandleGuard.Owner {

  private final long unsafeHandle;

  public KEMPublicKey(byte[] serialized, int offset) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.KyberPublicKey_DeserializeWithOffset(serialized, offset));
  }

  public KEMPublicKey(byte[] serialized) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.KyberPublicKey_DeserializeWithOffset(serialized, 0));
  }

  public KEMPublicKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.KyberPublicKey_Destroy(this.unsafeHandle);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.KyberPublicKey_Serialize(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) return false;
    if (!(other instanceof KEMPublicKey)) return false;
    try (NativeHandleGuard thisGuard = new NativeHandleGuard(this);
        NativeHandleGuard thatGuard = new NativeHandleGuard((KEMPublicKey) other); ) {
      return Native.KyberPublicKey_Equals(thisGuard.nativeHandle(), thatGuard.nativeHandle());
    }
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.serialize());
  }
}
