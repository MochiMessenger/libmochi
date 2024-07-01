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
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CreateCallLinkCredentialRequestContext extends ByteArray {

  public CreateCallLinkCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CreateCallLinkCredentialRequestContext_CheckValidContents(contents));
  }

  public static CreateCallLinkCredentialRequestContext forRoom(byte[] roomId) {
    return forRoom(roomId, new SecureRandom());
  }

  public static CreateCallLinkCredentialRequestContext forRoom(
      byte[] roomId, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.CreateCallLinkCredentialRequestContext_NewDeterministic(roomId, random);

    try {
      return new CreateCallLinkCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public CreateCallLinkCredentialRequest getRequest() {
    byte[] newContents = Native.CreateCallLinkCredentialRequestContext_GetRequest(contents);

    try {
      return new CreateCallLinkCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public CreateCallLinkCredential receiveResponse(
      CreateCallLinkCredentialResponse response, Aci userId, GenericServerPublicParams params)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                Native.CreateCallLinkCredentialRequestContext_ReceiveResponse(
                    getInternalContentsForJNI(),
                    response.getInternalContentsForJNI(),
                    userId.toServiceIdFixedWidthBinary(),
                    params.getInternalContentsForJNI()));

    try {
      return new CreateCallLinkCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
