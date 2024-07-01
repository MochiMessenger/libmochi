//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.usernames;

public class BadDiscriminatorException extends BaseUsernameException {
  public BadDiscriminatorException(String message) {
    super(message);
  }
}
