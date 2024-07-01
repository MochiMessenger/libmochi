//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

/** Error thrown by a failed CDSI lookup operation. */
public class CdsiInvalidTokenException extends Exception {
  public CdsiInvalidTokenException(String message) {
    super(message);
  }
}
