//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

import java.io.IOException;

/** Error thrown by a low-level network failure, for example failure to open a TCP connection. */
public class NetworkException extends IOException {
  public NetworkException(String message) {
    super(message);
  }
}
