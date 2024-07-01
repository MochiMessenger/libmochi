//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.usernames;

public final class DiscriminatorCannotHaveLeadingZerosException extends BadDiscriminatorException {
  public DiscriminatorCannotHaveLeadingZerosException(String message) {
    super(message);
  }
}
