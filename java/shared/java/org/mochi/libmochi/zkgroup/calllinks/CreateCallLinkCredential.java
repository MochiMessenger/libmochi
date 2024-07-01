//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.calllinks;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId.Aci;
import org.mochi.libmochi.zkgroup.GenericServerPublicParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CreateCallLinkCredential extends ByteArray {

  public CreateCallLinkCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CreateCallLinkCredential_CheckValidContents(contents));
  }

  public CreateCallLinkCredentialPresentation present(
      byte[] roomId,
      Aci userId,
      GenericServerPublicParams serverParams,
      CallLinkSecretParams callLinkParams) {
    return present(roomId, userId, serverParams, callLinkParams, new SecureRandom());
  }

  public CreateCallLinkCredentialPresentation present(
      byte[] roomId,
      Aci userId,
      GenericServerPublicParams serverParams,
      CallLinkSecretParams callLinkParams,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        filterExceptions(
            () ->
                Native.CreateCallLinkCredential_PresentDeterministic(
                    getInternalContentsForJNI(),
                    roomId,
                    userId.toServiceIdFixedWidthBinary(),
                    serverParams.getInternalContentsForJNI(),
                    callLinkParams.getInternalContentsForJNI(),
                    random));

    try {
      return new CreateCallLinkCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
