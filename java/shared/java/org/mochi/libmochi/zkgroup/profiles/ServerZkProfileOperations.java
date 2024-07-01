//
// Copyright 2020-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.profiles;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId.Aci;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.ServerSecretParams;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.groups.GroupPublicParams;

public class ServerZkProfileOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkProfileOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public ExpiringProfileKeyCredentialResponse issueExpiringProfileKeyCredential(
      ProfileKeyCredentialRequest profileKeyCredentialRequest,
      Aci userId,
      ProfileKeyCommitment profileKeyCommitment,
      Instant expiration)
      throws VerificationFailedException {
    return issueExpiringProfileKeyCredential(
        new SecureRandom(), profileKeyCredentialRequest, userId, profileKeyCommitment, expiration);
  }

  /**
   * Issues an ExpiringProfileKeyCredential.
   *
   * @param expiration Must be a round number of days. Use {@link java.time.Instant#truncatedTo} to
   *     ensure this.
   */
  public ExpiringProfileKeyCredentialResponse issueExpiringProfileKeyCredential(
      SecureRandom secureRandom,
      ProfileKeyCredentialRequest profileKeyCredentialRequest,
      Aci userId,
      ProfileKeyCommitment profileKeyCommitment,
      Instant expiration)
      throws VerificationFailedException {
    assert expiration.equals(expiration.truncatedTo(ChronoUnit.DAYS));

    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverSecretParams.guardedMapChecked(
                    (secretParams) ->
                        Native.ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(
                            secretParams,
                            random,
                            profileKeyCredentialRequest.getInternalContentsForJNI(),
                            userId.toServiceIdFixedWidthBinary(),
                            profileKeyCommitment.getInternalContentsForJNI(),
                            expiration.getEpochSecond())));

    try {
      return new ExpiringProfileKeyCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyProfileKeyCredentialPresentation(
      GroupPublicParams groupPublicParams,
      ProfileKeyCredentialPresentation profileKeyCredentialPresentation)
      throws VerificationFailedException {
    verifyProfileKeyCredentialPresentation(
        groupPublicParams, profileKeyCredentialPresentation, Instant.now());
  }

  public void verifyProfileKeyCredentialPresentation(
      GroupPublicParams groupPublicParams,
      ProfileKeyCredentialPresentation profileKeyCredentialPresentation,
      Instant now)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            serverSecretParams.guardedRunChecked(
                (secretParams) ->
                    Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(
                        secretParams,
                        groupPublicParams.getInternalContentsForJNI(),
                        profileKeyCredentialPresentation.getInternalContentsForJNI(),
                        now.getEpochSecond())));
  }
}
