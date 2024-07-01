//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

/** Indicates that the local application is too old, and was rejected by the server. */
public class AppExpiredException extends ChatServiceException {
  public AppExpiredException(String message) {
    super(message);
  }
}
