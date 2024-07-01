//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.usernames;

public final class NicknameTooShortException extends BaseUsernameException {
  public NicknameTooShortException(String message) {
    super(message);
  }
}
