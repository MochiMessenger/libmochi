//
// Copyright 2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.fingerprint;

public class FingerprintVersionMismatchException extends Exception {

  private final int theirVersion;
  private final int ourVersion;

  public FingerprintVersionMismatchException(int theirVersion, int ourVersion) {
    super();
    this.theirVersion = theirVersion;
    this.ourVersion = ourVersion;
  }

  public int getTheirVersion() {
    return theirVersion;
  }

  public int getOurVersion() {
    return ourVersion;
  }
}
