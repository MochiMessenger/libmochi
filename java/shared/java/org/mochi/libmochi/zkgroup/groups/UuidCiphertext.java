//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.groups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class UuidCiphertext extends ByteArray {
  public UuidCiphertext(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.UuidCiphertext_CheckValidContents(contents));
  }

  public static byte[] serializeAndConcatenate(Collection<UuidCiphertext> ciphertexts) {
    ByteArrayOutputStream concatenated = new ByteArrayOutputStream();
    for (UuidCiphertext member : ciphertexts) {
      try {
        concatenated.write(member.getInternalContentsForJNI());
      } catch (IOException e) {
        // ByteArrayOutputStream should never fail.
        throw new AssertionError(e);
      }
    }
    return concatenated.toByteArray();
  }
}
