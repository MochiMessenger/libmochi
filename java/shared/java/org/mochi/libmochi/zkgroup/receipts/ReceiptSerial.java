//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.receipts;

import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ReceiptSerial extends ByteArray {

  public static final int SIZE = 16;

  public ReceiptSerial(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }
}
