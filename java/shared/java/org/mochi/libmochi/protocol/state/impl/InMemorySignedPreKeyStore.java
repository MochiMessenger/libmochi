//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state.impl;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.mochi.libmochi.protocol.InvalidKeyIdException;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.state.SignedPreKeyRecord;
import org.mochi.libmochi.protocol.state.SignedPreKeyStore;

public class InMemorySignedPreKeyStore implements SignedPreKeyStore {

  private final Map<Integer, byte[]> store = new HashMap<>();

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    try {
      if (!store.containsKey(signedPreKeyId)) {
        throw new InvalidKeyIdException("No such SignedPreKeyRecord! " + signedPreKeyId);
      }

      return new SignedPreKeyRecord(store.get(signedPreKeyId));
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public List<SignedPreKeyRecord> loadSignedPreKeys() {
    try {
      List<SignedPreKeyRecord> results = new LinkedList<>();

      for (byte[] serialized : store.values()) {
        results.add(new SignedPreKeyRecord(serialized));
      }

      return results;
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
    store.put(signedPreKeyId, record.serialize());
  }

  @Override
  public boolean containsSignedPreKey(int signedPreKeyId) {
    return store.containsKey(signedPreKeyId);
  }

  @Override
  public void removeSignedPreKey(int signedPreKeyId) {
    store.remove(signedPreKeyId);
  }
}
