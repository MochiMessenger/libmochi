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
import org.mochi.libmochi.zkgroup.GenericServerSecretParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class CreateCallLinkCredentialRequest extends ByteArray {

  public CreateCallLinkCredentialRequest(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CreateCallLinkCredentialRequest_CheckValidContents(contents));
  }

  /**
   * Issues a CreateCallLinkCredential.
   *
   * @param userId The ACI of the user who will be creating the call link.
   * @param timestamp Must be a round number of days. Use {@link java.time.Instant#truncatedTo} to
   *     ensure this.
   * @param params The params that will be used by the calling server to verify this credential.
   */
  public CreateCallLinkCredentialResponse issueCredential(
      Aci userId, Instant timestamp, GenericServerSecretParams params) {
    return issueCredential(userId, timestamp, params, new SecureRandom());
  }

  /**
   * Issues a CreateCallLinkCredential, using a dedicated source of randomness.
   *
   * <p>This can be used to make tests deterministic. Prefer {@link #issueCredential(Aci, Instant,
   * GenericServerSecretParams)} if the source of randomness doesn't matter.
   *
   * @param userId The ACI of the user who will be creating the call link.
   * @param timestamp Must be a round number of days. Use {@link java.time.Instant#truncatedTo} to
   *     ensure this.
   * @param params The params that will be used by the calling server to verify this credential.
   * @param secureRandom Used to hide the server's secrets and make the issued credential unique.
   */
  public CreateCallLinkCredentialResponse issueCredential(
      Aci userId, Instant timestamp, GenericServerSecretParams params, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.CreateCallLinkCredentialRequest_IssueDeterministic(
            getInternalContentsForJNI(),
            userId.toServiceIdFixedWidthBinary(),
            timestamp.getEpochSecond(),
            params.getInternalContentsForJNI(),
            random);

    try {
      return new CreateCallLinkCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
