//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.receipts;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ReceiptCredentialRequestContext extends ByteArray {

  public static final int SIZE = 177;

  public ReceiptCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.ReceiptCredentialRequestContext_CheckValidContents(contents));
  }

  public ReceiptCredentialRequest getRequest() {
    byte[] newContents = Native.ReceiptCredentialRequestContext_GetRequest(contents);

    try {
      return new ReceiptCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
