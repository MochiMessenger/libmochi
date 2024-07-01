//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.ecc.ECKeyPair;
import org.mochi.libmochi.protocol.ecc.ECPrivateKey;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;

public class SignedPreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.SignedPreKeyRecord_Destroy(this.unsafeHandle);
  }

  public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
    try (NativeHandleGuard publicGuard = new NativeHandleGuard(keyPair.getPublicKey());
        NativeHandleGuard privateGuard = new NativeHandleGuard(keyPair.getPrivateKey()); ) {
      this.unsafeHandle =
          Native.SignedPreKeyRecord_New(
              id, timestamp, publicGuard.nativeHandle(), privateGuard.nativeHandle(), signature);
    }
  }

  // FIXME: This shouldn't be considered a "message".
  public SignedPreKeyRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle =
        filterExceptions(
            InvalidMessageException.class, () -> Native.SignedPreKeyRecord_Deserialize(serialized));
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SignedPreKeyRecord_GetId(guard.nativeHandle()));
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SignedPreKeyRecord_GetTimestamp(guard.nativeHandle()));
    }
  }

  public ECKeyPair getKeyPair() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> {
            ECPublicKey publicKey =
                new ECPublicKey(Native.SignedPreKeyRecord_GetPublicKey(guard.nativeHandle()));
            ECPrivateKey privateKey =
                new ECPrivateKey(Native.SignedPreKeyRecord_GetPrivateKey(guard.nativeHandle()));
            return new ECKeyPair(publicKey, privateKey);
          });
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SignedPreKeyRecord_GetSignature(guard.nativeHandle()));
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SignedPreKeyRecord_GetSerialized(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
