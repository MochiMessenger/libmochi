//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.auth;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId.Aci;
import org.mochi.libmochi.protocol.ServiceId.Pni;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.ServerPublicParams;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.groups.GroupSecretParams;

public class ClientZkAuthOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkAuthOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  /**
   * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
   *
   * @param redemptionTime This is provided by the server as an integer, and should be passed
   *     through directly.
   */
  public AuthCredentialWithPni receiveAuthCredentialWithPniAsServiceId(
      Aci aci, Pni pni, long redemptionTime, AuthCredentialWithPniResponse authCredentialResponse)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverPublicParams.guardedMapChecked(
                    (publicParams) ->
                        Native.ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(
                            publicParams,
                            aci.toServiceIdFixedWidthBinary(),
                            pni.toServiceIdFixedWidthBinary(),
                            redemptionTime,
                            authCredentialResponse.getInternalContentsForJNI())));

    try {
      return new AuthCredentialWithPni(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public AuthCredentialPresentation createAuthCredentialPresentation(
      GroupSecretParams groupSecretParams, AuthCredentialWithPni authCredential) {
    return createAuthCredentialPresentation(new SecureRandom(), groupSecretParams, authCredential);
  }

  public AuthCredentialPresentation createAuthCredentialPresentation(
      SecureRandom secureRandom,
      GroupSecretParams groupSecretParams,
      AuthCredentialWithPni authCredential) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverPublicParams.guardedMap(
            (publicParams) ->
                Native.ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
                    publicParams,
                    random,
                    groupSecretParams.getInternalContentsForJNI(),
                    authCredential.getInternalContentsForJNI()));

    try {
      return new AuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
