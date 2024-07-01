//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

public class DuplicateMessageException extends Exception {
  public DuplicateMessageException(String s) {
    super(s);
  }
}
