//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.auth;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId.Aci;
import org.mochi.libmochi.protocol.ServiceId.Pni;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.ServerSecretParams;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.groups.GroupPublicParams;

public class ServerZkAuthOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkAuthOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniAsServiceId(
      Aci aci, Pni pni, Instant redemptionTime) {
    return issueAuthCredentialWithPniAsServiceId(new SecureRandom(), aci, pni, redemptionTime);
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniAsServiceId(
      SecureRandom secureRandom, Aci aci, Pni pni, Instant redemptionTime) {
    byte[] random = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents =
        serverSecretParams.guardedMap(
            (serverSecretParams) ->
                Native.ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic(
                    serverSecretParams,
                    random,
                    aci.toServiceIdFixedWidthBinary(),
                    pni.toServiceIdFixedWidthBinary(),
                    redemptionTime.getEpochSecond()));

    try {
      return new AuthCredentialWithPniResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniZkc(
      Aci aci, Pni pni, Instant redemptionTime) {
    return issueAuthCredentialWithPniZkc(new SecureRandom(), aci, pni, redemptionTime);
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniZkc(
      SecureRandom secureRandom, Aci aci, Pni pni, Instant redemptionTime) {
    byte[] random = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents =
        serverSecretParams.guardedMap(
            (serverSecretParams) ->
                Native.ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(
                    serverSecretParams,
                    random,
                    aci.toServiceIdFixedWidthBinary(),
                    pni.toServiceIdFixedWidthBinary(),
                    redemptionTime.getEpochSecond()));

    try {
      return new AuthCredentialWithPniResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyAuthCredentialPresentation(
      GroupPublicParams groupPublicParams, AuthCredentialPresentation authCredentialPresentation)
      throws VerificationFailedException {
    verifyAuthCredentialPresentation(groupPublicParams, authCredentialPresentation, Instant.now());
  }

  public void verifyAuthCredentialPresentation(
      GroupPublicParams groupPublicParams,
      AuthCredentialPresentation authCredentialPresentation,
      Instant currentTime)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            serverSecretParams.guardedRunChecked(
                (secretParams) ->
                    Native.ServerSecretParams_VerifyAuthCredentialPresentation(
                        secretParams,
                        groupPublicParams.getInternalContentsForJNI(),
                        authCredentialPresentation.getInternalContentsForJNI(),
                        currentTime.getEpochSecond())));
  }
}
