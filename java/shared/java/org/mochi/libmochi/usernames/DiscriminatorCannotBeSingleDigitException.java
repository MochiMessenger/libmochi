//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.usernames;

public final class DiscriminatorCannotBeSingleDigitException extends BadDiscriminatorException {
  public DiscriminatorCannotBeSingleDigitException(String message) {
    super(message);
  }
}
