//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.hsmenclave;

public class EnclaveCommunicationFailureException extends Exception {
  public EnclaveCommunicationFailureException(String msg) {
    super(msg);
  }

  public EnclaveCommunicationFailureException(Throwable t) {
    super(t);
  }
}
