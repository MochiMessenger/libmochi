//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.ecc.Curve;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;
import org.mochi.libmochi.protocol.util.Hex;

/**
 * A class for representing an identity key.
 *
 * @author Moxie Marlinspike
 */
public class IdentityKey {

  private final ECPublicKey publicKey;

  public IdentityKey(ECPublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public IdentityKey(byte[] bytes, int offset) throws InvalidKeyException {
    this.publicKey = Curve.decodePoint(bytes, offset);
  }

  public IdentityKey(byte[] bytes) throws InvalidKeyException {
    this.publicKey = Curve.decodePoint(bytes, 0);
  }

  public IdentityKey(long nativeHandle) {
    this.publicKey = new ECPublicKey(nativeHandle);
  }

  public ECPublicKey getPublicKey() {
    return publicKey;
  }

  public byte[] serialize() {
    return publicKey.serialize();
  }

  public String getFingerprint() {
    return Hex.toString(publicKey.serialize());
  }

  public boolean verifyAlternateIdentity(IdentityKey other, byte[] signature) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this.publicKey);
        NativeHandleGuard otherGuard = new NativeHandleGuard(other.publicKey); ) {
      return filterExceptions(
          () ->
              Native.IdentityKey_VerifyAlternateIdentity(
                  guard.nativeHandle(), otherGuard.nativeHandle(), signature));
    }
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) return false;
    if (!(other instanceof IdentityKey)) return false;

    return publicKey.equals(((IdentityKey) other).getPublicKey());
  }

  @Override
  public int hashCode() {
    return publicKey.hashCode();
  }
}
