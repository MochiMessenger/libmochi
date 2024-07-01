//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.groups;

import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class GroupIdentifier extends ByteArray {

  public static final int SIZE = 32;

  public GroupIdentifier(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }
}
