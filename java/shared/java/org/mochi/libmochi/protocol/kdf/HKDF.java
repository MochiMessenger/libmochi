//
// Copyright 2013-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.kdf;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;

public abstract class HKDF {
  public static byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    return filterExceptions(
        () -> Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, null));
  }

  public static byte[] deriveSecrets(
      byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
    return filterExceptions(
        () -> Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, salt));
  }
}
