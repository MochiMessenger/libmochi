//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.kem;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidKeyException;

public class KEMSecretKey implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public KEMSecretKey(byte[] privateKey) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class, () -> Native.KyberSecretKey_Deserialize(privateKey));
  }

  public KEMSecretKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.KyberSecretKey_Destroy(this.unsafeHandle);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.KyberSecretKey_Serialize(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
