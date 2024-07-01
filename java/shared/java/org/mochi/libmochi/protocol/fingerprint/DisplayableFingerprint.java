//
// Copyright 2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.fingerprint;

public class DisplayableFingerprint {
  private String displayString;

  DisplayableFingerprint(String displayString) {
    this.displayString = displayString;
  }

  public String getDisplayText() {
    return this.displayString;
  }
}
