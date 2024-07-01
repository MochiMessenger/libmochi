//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.Arrays;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.zkgroup.internal.ByteArray;

public final class ServerPublicParams extends NativeHandleGuard.SimpleOwner {
  public ServerPublicParams(byte[] contents) throws InvalidInputException {
    super(filterExceptions(() -> Native.ServerPublicParams_Deserialize(contents)));
  }

  ServerPublicParams(long nativeHandle) {
    super(nativeHandle);
  }

  @Override
  protected void release(long handle) {
    Native.ServerPublicParams_Destroy(handle);
  }

  public void verifySignature(byte[] message, NotarySignature notarySignature)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            this.guardedRunChecked(
                (serverPublicParams) ->
                    Native.ServerPublicParams_VerifySignature(
                        serverPublicParams, message, notarySignature.getInternalContentsForJNI())));
  }

  public byte[] serialize() {
    return guardedMap(Native::ServerPublicParams_Serialize);
  }

  @Override
  public int hashCode() {
    return getClass().hashCode() * 31 + Arrays.hashCode(serialize());
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;

    ServerPublicParams other = (ServerPublicParams) o;
    return ByteArray.constantTimeEqual(this.serialize(), other.serialize());
  }
}
