//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.receipts;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ReceiptCredentialPresentation extends ByteArray {
  public ReceiptCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () ->
            filterExceptions(
                InvalidInputException.class,
                () -> Native.ReceiptCredentialPresentation_CheckValidContents(contents)));
  }

  public long getReceiptExpirationTime() {
    return Native.ReceiptCredentialPresentation_GetReceiptExpirationTime(contents);
  }

  public long getReceiptLevel() {
    return Native.ReceiptCredentialPresentation_GetReceiptLevel(contents);
  }

  public ReceiptSerial getReceiptSerial() {
    byte[] newContents = Native.ReceiptCredentialPresentation_GetReceiptSerial(contents);

    try {
      return new ReceiptSerial(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
