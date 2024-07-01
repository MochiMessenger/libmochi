//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.backups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.GenericServerPublicParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class BackupAuthCredential extends ByteArray {

  public BackupAuthCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.BackupAuthCredential_CheckValidContents(contents));
  }

  public BackupAuthCredentialPresentation present(GenericServerPublicParams serverParams) {
    return present(serverParams, new SecureRandom());
  }

  public BackupAuthCredentialPresentation present(
      GenericServerPublicParams serverParams, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    final byte[] newContents =
        filterExceptions(
            () ->
                Native.BackupAuthCredential_PresentDeterministic(
                    getInternalContentsForJNI(), serverParams.getInternalContentsForJNI(), random));

    try {
      return new BackupAuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] getBackupId() {
    return Native.BackupAuthCredential_GetBackupId(getInternalContentsForJNI());
  }

  public BackupLevel getBackupLevel() {
    return BackupLevel.fromValue(
        Native.BackupAuthCredential_GetBackupLevel(getInternalContentsForJNI()));
  }
}
