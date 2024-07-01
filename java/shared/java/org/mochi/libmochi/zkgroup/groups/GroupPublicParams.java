//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.groups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class GroupPublicParams extends ByteArray {

  public GroupPublicParams(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.GroupPublicParams_CheckValidContents(contents));
  }

  public GroupIdentifier getGroupIdentifier() {
    byte[] newContents = Native.GroupPublicParams_GetGroupIdentifier(contents);

    try {
      return new GroupIdentifier(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
