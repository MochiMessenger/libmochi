//
// Copyright 2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.cds2;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.attest.AttestationDataException;
import org.mochi.libmochi.attest.AttestationFailedException;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.sgxsession.SgxClient;

/**
 * Cds2Client provides bindings to interact with Mochi's v2 Contact Discovery Service.
 *
 * <p>{@inheritDoc}
 *
 * <p>A future update to Cds2Client will implement additional parts of the contact discovery
 * protocol.
 */
public class Cds2Client extends SgxClient {
  public Cds2Client(byte[] mrenclave, byte[] attestationMsg, Instant currentInstant)
      throws AttestationDataException, AttestationFailedException {
    super(
        filterExceptions(
            AttestationDataException.class,
            AttestationFailedException.class,
            () ->
                Native.Cds2ClientState_New(
                    mrenclave, attestationMsg, currentInstant.toEpochMilli())));
  }
}
