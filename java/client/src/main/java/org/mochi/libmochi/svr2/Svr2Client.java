//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.svr2;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.attest.AttestationDataException;
import org.mochi.libmochi.attest.AttestationFailedException;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.sgxsession.SgxClient;

/**
 * Svr2Client provides bindings to interact with Mochi's v2 Secure Value Recovery service.
 *
 * <p>
 *
 * <p>{@inheritDoc}
 */
public class Svr2Client extends SgxClient {
  public Svr2Client(byte[] mrenclave, byte[] attestationMsg, Instant currentInstant)
      throws AttestationDataException, AttestationFailedException {
    super(
        filterExceptions(
            AttestationDataException.class,
            AttestationFailedException.class,
            () -> Native.Svr2Client_New(mrenclave, attestationMsg, currentInstant.toEpochMilli())));
  }
}
