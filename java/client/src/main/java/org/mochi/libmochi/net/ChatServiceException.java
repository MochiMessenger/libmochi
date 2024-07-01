//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

/** Error thrown by Chat Service API. */
public class ChatServiceException extends Exception {
  public ChatServiceException(String message) {
    super(message);
  }
}
