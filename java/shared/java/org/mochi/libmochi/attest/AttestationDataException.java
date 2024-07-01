//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.attest;

/** Attestation data was malformed. */
public class AttestationDataException extends Exception {
  public AttestationDataException(String msg) {
    super(msg);
  }

  public AttestationDataException(Throwable t) {
    super(t);
  }
}
