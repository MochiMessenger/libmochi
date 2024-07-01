//
// Copyright 2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.profiles;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ExpiringProfileKeyCredential extends ByteArray {
  public ExpiringProfileKeyCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.ExpiringProfileKeyCredential_CheckValidContents(contents));
  }

  public Instant getExpirationTime() {
    return Instant.ofEpochSecond(
        Native.ExpiringProfileKeyCredential_GetExpirationTime(this.contents));
  }
}
