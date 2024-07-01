//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.svr;

public final class DataMissingException extends SvrException {
  public DataMissingException(String message) {
    super(message);
  }
}
