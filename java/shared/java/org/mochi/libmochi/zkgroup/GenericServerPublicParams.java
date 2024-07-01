//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class GenericServerPublicParams extends ByteArray {
  public GenericServerPublicParams(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.GenericServerPublicParams_CheckValidContents(contents));
  }
}
