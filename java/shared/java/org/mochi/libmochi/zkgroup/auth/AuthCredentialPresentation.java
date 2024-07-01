//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.auth;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.groups.UuidCiphertext;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class AuthCredentialPresentation extends ByteArray {

  public enum Version {
    V1,
    V2,
    V3,
    V4,
    UNKNOWN
  };

  public AuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AuthCredentialPresentation_CheckValidContents(contents));
  }

  public UuidCiphertext getUuidCiphertext() {
    byte[] newContents = Native.AuthCredentialPresentation_GetUuidCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /** Returns the PNI ciphertext for this credential. May be {@code null}. */
  public UuidCiphertext getPniCiphertext() {
    byte[] newContents = Native.AuthCredentialPresentation_GetPniCiphertext(contents);
    if (newContents == null) {
      return null;
    }

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public Instant getRedemptionTime() {
    return Instant.ofEpochSecond(Native.AuthCredentialPresentation_GetRedemptionTime(contents));
  }

  public Version getVersion() {
    byte version = this.contents[0];
    final Version[] values = Version.values();
    if (version < values.length) {
      return values[version];
    }
    return Version.UNKNOWN;
  }
}
