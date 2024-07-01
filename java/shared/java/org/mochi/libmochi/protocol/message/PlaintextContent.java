//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.message;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.InvalidVersionException;

public final class PlaintextContent implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.PlaintextContent_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  // Used by Rust.
  @SuppressWarnings("unused")
  private PlaintextContent(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public PlaintextContent(DecryptionErrorMessage message) {
    try (NativeHandleGuard messageGuard = new NativeHandleGuard(message)) {
      this.unsafeHandle =
          Native.PlaintextContent_FromDecryptionErrorMessage(messageGuard.nativeHandle());
    }
  }

  public PlaintextContent(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException {
    unsafeHandle =
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            () -> Native.PlaintextContent_Deserialize(serialized));
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.PlaintextContent_GetSerialized(guard.nativeHandle()));
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.PLAINTEXT_CONTENT_TYPE;
  }

  public byte[] getBody() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.PlaintextContent_GetBody(guard.nativeHandle()));
    }
  }
}
