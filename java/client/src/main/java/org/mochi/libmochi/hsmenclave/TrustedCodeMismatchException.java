//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.hsmenclave;

public class TrustedCodeMismatchException extends Exception {
  public TrustedCodeMismatchException(String msg) {
    super(msg);
  }

  public TrustedCodeMismatchException(Throwable t) {
    super(t);
  }
}
