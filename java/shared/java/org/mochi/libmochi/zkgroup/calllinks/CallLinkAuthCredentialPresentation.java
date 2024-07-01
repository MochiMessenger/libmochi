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
import org.mochi.libmochi.zkgroup.groups.UuidCiphertext;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CallLinkAuthCredentialPresentation extends ByteArray {

  public CallLinkAuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CallLinkAuthCredentialPresentation_CheckValidContents(contents));
  }

  public void verify(GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams)
      throws VerificationFailedException {
    verify(Instant.now(), serverParams, callLinkParams);
  }

  public void verify(
      Instant currentTime,
      GenericServerSecretParams serverParams,
      CallLinkPublicParams callLinkParams)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.CallLinkAuthCredentialPresentation_Verify(
                getInternalContentsForJNI(),
                currentTime.getEpochSecond(),
                serverParams.getInternalContentsForJNI(),
                callLinkParams.getInternalContentsForJNI()));
  }

  public UuidCiphertext getUserId() {
    byte[] newContents = Native.CallLinkAuthCredentialPresentation_GetUserId(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
