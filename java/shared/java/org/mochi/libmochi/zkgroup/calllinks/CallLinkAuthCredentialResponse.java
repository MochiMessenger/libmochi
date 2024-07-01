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
import org.mochi.libmochi.zkgroup.GenericServerSecretParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CallLinkAuthCredentialResponse extends ByteArray {
  public CallLinkAuthCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CallLinkAuthCredentialResponse_CheckValidContents(contents));
  }

  public static CallLinkAuthCredentialResponse issueCredential(
      Aci userId, Instant redemptionTime, GenericServerSecretParams params) {
    return issueCredential(userId, redemptionTime, params, new SecureRandom());
  }

  public static CallLinkAuthCredentialResponse issueCredential(
      Aci userId,
      Instant redemptionTime,
      GenericServerSecretParams params,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.CallLinkAuthCredentialResponse_IssueDeterministic(
            userId.toServiceIdFixedWidthBinary(),
            redemptionTime.getEpochSecond(),
            params.getInternalContentsForJNI(),
            random);

    try {
      return new CallLinkAuthCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public CallLinkAuthCredential receive(
      Aci userId, Instant redemptionTime, GenericServerPublicParams params)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                Native.CallLinkAuthCredentialResponse_Receive(
                    getInternalContentsForJNI(),
                    userId.toServiceIdFixedWidthBinary(),
                    redemptionTime.getEpochSecond(),
                    params.getInternalContentsForJNI()));

    try {
      return new CallLinkAuthCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
