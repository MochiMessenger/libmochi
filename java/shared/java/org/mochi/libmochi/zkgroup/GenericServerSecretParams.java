//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class GenericServerSecretParams extends ByteArray {

  public static GenericServerSecretParams generate() {
    return generate(new SecureRandom());
  }

  public static GenericServerSecretParams generate(SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.GenericServerSecretParams_GenerateDeterministic(random);

    try {
      return new GenericServerSecretParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public GenericServerSecretParams(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.GenericServerSecretParams_CheckValidContents(contents));
  }

  public GenericServerPublicParams getPublicParams() {
    byte[] newContents = Native.GenericServerSecretParams_GetPublicParams(contents);
    try {
      return new GenericServerPublicParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
