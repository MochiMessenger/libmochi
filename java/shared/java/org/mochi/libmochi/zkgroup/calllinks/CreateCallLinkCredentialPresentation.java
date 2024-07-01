//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.calllinks;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.GenericServerSecretParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CreateCallLinkCredentialPresentation extends ByteArray {

  public CreateCallLinkCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CreateCallLinkCredentialPresentation_CheckValidContents(contents));
  }

  public void verify(
      byte[] roomId, GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams)
      throws VerificationFailedException {
    verify(roomId, Instant.now(), serverParams, callLinkParams);
  }

  public void verify(
      byte[] roomId,
      Instant currentTime,
      GenericServerSecretParams serverParams,
      CallLinkPublicParams callLinkParams)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.CreateCallLinkCredentialPresentation_Verify(
                getInternalContentsForJNI(),
                roomId,
                currentTime.getEpochSecond(),
                serverParams.getInternalContentsForJNI(),
                callLinkParams.getInternalContentsForJNI()));
  }
}
