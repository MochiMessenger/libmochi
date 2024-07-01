//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.crypto;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidKeyException;

public class Aes256Ctr32 implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public Aes256Ctr32(byte[] key, byte[] nonce, int initialCtr) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class, () -> Native.Aes256Ctr32_New(key, nonce, initialCtr));
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.Aes256Ctr32_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public void process(byte[] data) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256Ctr32_Process(guard.nativeHandle(), data, 0, data.length);
    }
  }

  public void process(byte[] data, int offset, int length) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256Ctr32_Process(guard.nativeHandle(), data, offset, length);
    }
  }
}
