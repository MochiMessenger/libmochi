//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.profiles;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId.Aci;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ProfileKey extends ByteArray {

  public ProfileKey(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () ->
            filterExceptions(
                InvalidInputException.class, () -> Native.ProfileKey_CheckValidContents(contents)));
  }

  public ProfileKeyCommitment getCommitment(Aci userId) {
    byte[] newContents =
        Native.ProfileKey_GetCommitment(contents, userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKeyCommitment(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyVersion getProfileKeyVersion(Aci userId) {
    byte[] newContents =
        Native.ProfileKey_GetProfileKeyVersion(contents, userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKeyVersion(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] deriveAccessKey() {
    return Native.ProfileKey_DeriveAccessKey(contents);
  }
}
