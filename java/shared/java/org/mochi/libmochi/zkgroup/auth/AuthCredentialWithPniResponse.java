//
// Copyright 2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.auth;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class AuthCredentialWithPniResponse extends ByteArray {
  public AuthCredentialWithPniResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AuthCredentialWithPniResponse_CheckValidContents(contents));
  }
}
