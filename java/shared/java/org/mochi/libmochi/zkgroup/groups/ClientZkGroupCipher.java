//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.groups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.protocol.ServiceId;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.profiles.ProfileKey;

public class ClientZkGroupCipher {

  private final GroupSecretParams groupSecretParams;

  public ClientZkGroupCipher(GroupSecretParams groupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  public UuidCiphertext encrypt(ServiceId serviceId) {
    byte[] newContents =
        Native.GroupSecretParams_EncryptServiceId(
            groupSecretParams.getInternalContentsForJNI(), serviceId.toServiceIdFixedWidthBinary());

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ServiceId decrypt(UuidCiphertext uuidCiphertext) throws VerificationFailedException {
    try {
      return ServiceId.parseFromFixedWidthBinary(
          filterExceptions(
              VerificationFailedException.class,
              () ->
                  Native.GroupSecretParams_DecryptServiceId(
                      groupSecretParams.getInternalContentsForJNI(),
                      uuidCiphertext.getInternalContentsForJNI())));
    } catch (ServiceId.InvalidServiceIdException e) {
      throw new VerificationFailedException();
    }
  }

  public ProfileKeyCiphertext encryptProfileKey(ProfileKey profileKey, ServiceId.Aci userId) {
    byte[] newContents =
        Native.GroupSecretParams_EncryptProfileKey(
            groupSecretParams.getInternalContentsForJNI(),
            profileKey.getInternalContentsForJNI(),
            userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKeyCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKey decryptProfileKey(
      ProfileKeyCiphertext profileKeyCiphertext, ServiceId.Aci userId)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                Native.GroupSecretParams_DecryptProfileKey(
                    groupSecretParams.getInternalContentsForJNI(),
                    profileKeyCiphertext.getInternalContentsForJNI(),
                    userId.toServiceIdFixedWidthBinary()));

    try {
      return new ProfileKey(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] encryptBlob(byte[] plaintext) throws VerificationFailedException {
    return encryptBlob(new SecureRandom(), plaintext);
  }

  public byte[] encryptBlob(SecureRandom secureRandom, byte[] plaintext)
      throws VerificationFailedException {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);
    return Native.GroupSecretParams_EncryptBlobWithPaddingDeterministic(
        groupSecretParams.getInternalContentsForJNI(), random, plaintext, 0);
  }

  public byte[] decryptBlob(byte[] blobCiphertext) throws VerificationFailedException {
    return filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.GroupSecretParams_DecryptBlobWithPadding(
                groupSecretParams.getInternalContentsForJNI(), blobCiphertext));
  }
}
