//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.crypto;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;

public class CryptographicMac implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public CryptographicMac(String algo, byte[] key) {
    this.unsafeHandle = filterExceptions(() -> Native.CryptographicMac_New(algo, key));
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.CryptographicMac_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public void update(byte[] input, int offset, int len) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.CryptographicMac_UpdateWithOffset(guard.nativeHandle(), input, offset, len);
    }
  }

  public void update(byte[] input) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.CryptographicMac_Update(guard.nativeHandle(), input);
    }
  }

  public byte[] finish() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.CryptographicMac_Finalize(guard.nativeHandle());
    }
  }
}
