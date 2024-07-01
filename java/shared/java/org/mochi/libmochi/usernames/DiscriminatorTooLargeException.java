//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.usernames;

public final class DiscriminatorTooLargeException extends BadDiscriminatorException {
  public DiscriminatorTooLargeException(String message) {
    super(message);
  }
}
