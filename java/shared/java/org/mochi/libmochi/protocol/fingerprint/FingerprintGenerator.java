//
// Copyright 2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.fingerprint;

import org.mochi.libmochi.protocol.IdentityKey;

public interface FingerprintGenerator {
  public Fingerprint createFor(
      int version,
      byte[] localStableIdentifier,
      IdentityKey localIdentityKey,
      byte[] remoteStableIdentifier,
      IdentityKey remoteIdentityKey);
}
