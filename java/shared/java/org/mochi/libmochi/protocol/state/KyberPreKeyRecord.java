//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.kem.KEMKeyPair;

public class KyberPreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.KyberPreKeyRecord_Destroy(this.unsafeHandle);
  }

  public KyberPreKeyRecord(int id, long timestamp, KEMKeyPair keyPair, byte[] signature) {
    try (NativeHandleGuard guard = new NativeHandleGuard(keyPair)) {
      this.unsafeHandle =
          Native.KyberPreKeyRecord_New(id, timestamp, guard.nativeHandle(), signature);
    }
  }

  // FIXME: This shouldn't be considered a "message".
  public KyberPreKeyRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle =
        filterExceptions(
            InvalidMessageException.class, () -> Native.KyberPreKeyRecord_Deserialize(serialized));
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.KyberPreKeyRecord_GetId(guard.nativeHandle()));
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.KyberPreKeyRecord_GetTimestamp(guard.nativeHandle()));
    }
  }

  public KEMKeyPair getKeyPair() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new KEMKeyPair(
          filterExceptions(() -> Native.KyberPreKeyRecord_GetKeyPair(guard.nativeHandle())));
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.KyberPreKeyRecord_GetSignature(guard.nativeHandle()));
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.KyberPreKeyRecord_GetSerialized(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
