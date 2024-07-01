//
// Copyright 2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.cds2;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.Map;
import org.mochi.libmochi.attest.AttestationDataException;
import org.mochi.libmochi.internal.Native;

public final class Cds2Metrics {

  private Cds2Metrics() {}

  /**
   * Parse a cds2 attestation response (ClientHandshakeStart) and return supplemental information
   * extracted from the response's evidence and endorsements.
   *
   * @param attestationMessage A ClientHandshakeStart message
   * @throws AttestationDataException if the attestationMessage cannot be parsed
   */
  public static Map<String, Long> extract(final byte[] attestationMessage)
      throws AttestationDataException {
    @SuppressWarnings("unchecked")
    Map<String, Long> result =
        filterExceptions(
            AttestationDataException.class, () -> Native.Cds2Metrics_extract(attestationMessage));
    return result;
  }
}
