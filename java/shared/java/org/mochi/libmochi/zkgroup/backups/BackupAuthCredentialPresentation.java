//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.backups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.GenericServerSecretParams;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class BackupAuthCredentialPresentation extends ByteArray {

  public BackupAuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.BackupAuthCredentialPresentation_CheckValidContents(contents));
  }

  public void verify(GenericServerSecretParams serverParams) throws VerificationFailedException {
    verify(Instant.now(), serverParams);
  }

  public void verify(Instant currentTime, GenericServerSecretParams serverParams)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.BackupAuthCredentialPresentation_Verify(
                getInternalContentsForJNI(),
                currentTime.getEpochSecond(),
                serverParams.getInternalContentsForJNI()));
  }

  public byte[] getBackupId() {
    return Native.BackupAuthCredentialPresentation_GetBackupId(getInternalContentsForJNI());
  }

  public BackupLevel getBackupLevel() {
    return BackupLevel.fromValue(
        Native.BackupAuthCredentialPresentation_GetBackupLevel(getInternalContentsForJNI()));
  }
}
