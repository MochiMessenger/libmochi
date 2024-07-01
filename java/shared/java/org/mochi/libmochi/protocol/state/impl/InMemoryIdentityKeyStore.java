//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state.impl;

import java.util.HashMap;
import java.util.Map;
import org.mochi.libmochi.protocol.IdentityKey;
import org.mochi.libmochi.protocol.IdentityKeyPair;
import org.mochi.libmochi.protocol.MochiProtocolAddress;
import org.mochi.libmochi.protocol.state.IdentityKeyStore;

public class InMemoryIdentityKeyStore implements IdentityKeyStore {

  private final Map<MochiProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();

  private final IdentityKeyPair identityKeyPair;
  private final int localRegistrationId;

  public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId) {
    this.identityKeyPair = identityKeyPair;
    this.localRegistrationId = localRegistrationId;
  }

  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }

  @Override
  public int getLocalRegistrationId() {
    return localRegistrationId;
  }

  @Override
  public boolean saveIdentity(MochiProtocolAddress address, IdentityKey identityKey) {
    IdentityKey existing = trustedKeys.get(address);

    if (!identityKey.equals(existing)) {
      trustedKeys.put(address, identityKey);
      return true;
    } else {
      return false;
    }
  }

  @Override
  public boolean isTrustedIdentity(
      MochiProtocolAddress address, IdentityKey identityKey, Direction direction) {
    IdentityKey trusted = trustedKeys.get(address);
    return (trusted == null || trusted.equals(identityKey));
  }

  @Override
  public IdentityKey getIdentity(MochiProtocolAddress address) {
    return trustedKeys.get(address);
  }
}
