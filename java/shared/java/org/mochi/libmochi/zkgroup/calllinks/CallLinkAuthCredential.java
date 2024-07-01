//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.calllinks;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId.Aci;
import org.mochi.libmochi.zkgroup.GenericServerPublicParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CallLinkAuthCredential extends ByteArray {

  public CallLinkAuthCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CallLinkAuthCredential_CheckValidContents(contents));
  }

  public CallLinkAuthCredentialPresentation present(
      Aci userId,
      Instant redemptionTime,
      GenericServerPublicParams serverParams,
      CallLinkSecretParams callLinkParams) {
    return present(userId, redemptionTime, serverParams, callLinkParams, new SecureRandom());
  }

  public CallLinkAuthCredentialPresentation present(
      Aci userId,
      Instant redemptionTime,
      GenericServerPublicParams serverParams,
      CallLinkSecretParams callLinkParams,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        filterExceptions(
            () ->
                Native.CallLinkAuthCredential_PresentDeterministic(
                    getInternalContentsForJNI(),
                    userId.toServiceIdFixedWidthBinary(),
                    redemptionTime.getEpochSecond(),
                    serverParams.getInternalContentsForJNI(),
                    callLinkParams.getInternalContentsForJNI(),
                    random));

    try {
      return new CallLinkAuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
