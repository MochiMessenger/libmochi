//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.profiles;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.groups.ProfileKeyCiphertext;
import org.mochi.libmochi.zkgroup.groups.UuidCiphertext;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ProfileKeyCredentialPresentation extends ByteArray {

  public enum Version {
    V1,
    V2,
    V3,
    UNKNOWN
  };

  public ProfileKeyCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.ProfileKeyCredentialPresentation_CheckValidContents(contents));
  }

  public UuidCiphertext getUuidCiphertext() {
    byte[] newContents = Native.ProfileKeyCredentialPresentation_GetUuidCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyCiphertext getProfileKeyCiphertext() {
    byte[] newContents = Native.ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(contents);

    try {
      return new ProfileKeyCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] getStructurallyValidV1PresentationBytes() {
    return Native.ProfileKeyCredentialPresentation_GetStructurallyValidV1PresentationBytes(
        contents);
  }

  public Version getVersion() {
    switch (this.contents[0]) {
      case 0:
        return Version.V1;
      case 1:
        return Version.V2;
      case 2:
        return Version.V3;
      default:
        return Version.UNKNOWN;
    }
  }
}
