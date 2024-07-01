//
// Copyright 2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.fingerprint;

public class Fingerprint {

  private final DisplayableFingerprint displayableFingerprint;
  private final ScannableFingerprint scannableFingerprint;

  public Fingerprint(
      DisplayableFingerprint displayableFingerprint, ScannableFingerprint scannableFingerprint) {
    this.displayableFingerprint = displayableFingerprint;
    this.scannableFingerprint = scannableFingerprint;
  }

  /**
   * @return A text fingerprint that can be displayed and compared remotely.
   */
  public DisplayableFingerprint getDisplayableFingerprint() {
    return displayableFingerprint;
  }

  /**
   * @return A scannable fingerprint that can be scanned and compared locally.
   */
  public ScannableFingerprint getScannableFingerprint() {
    return scannableFingerprint;
  }
}
