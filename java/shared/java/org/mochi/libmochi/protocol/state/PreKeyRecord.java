//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidKeyException;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.ecc.ECKeyPair;
import org.mochi.libmochi.protocol.ecc.ECPrivateKey;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;

public class PreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.PreKeyRecord_Destroy(this.unsafeHandle);
  }

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    try (NativeHandleGuard publicKey = new NativeHandleGuard(keyPair.getPublicKey());
        NativeHandleGuard privateKey = new NativeHandleGuard(keyPair.getPrivateKey()); ) {
      this.unsafeHandle =
          Native.PreKeyRecord_New(id, publicKey.nativeHandle(), privateKey.nativeHandle());
    }
  }

  // FIXME: This shouldn't be considered a "message".
  public PreKeyRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle =
        filterExceptions(
            InvalidMessageException.class, () -> Native.PreKeyRecord_Deserialize(serialized));
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.PreKeyRecord_GetId(guard.nativeHandle()));
    }
  }

  public ECKeyPair getKeyPair() throws InvalidKeyException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          InvalidKeyException.class,
          () -> {
            ECPublicKey publicKey =
                new ECPublicKey(Native.PreKeyRecord_GetPublicKey(guard.nativeHandle()));
            ECPrivateKey privateKey =
                new ECPrivateKey(Native.PreKeyRecord_GetPrivateKey(guard.nativeHandle()));
            return new ECKeyPair(publicKey, privateKey);
          });
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.PreKeyRecord_GetSerialized(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
