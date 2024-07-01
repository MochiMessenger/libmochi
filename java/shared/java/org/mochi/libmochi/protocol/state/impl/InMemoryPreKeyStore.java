//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state.impl;

import java.util.HashMap;
import java.util.Map;
import org.mochi.libmochi.protocol.InvalidKeyIdException;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.state.PreKeyRecord;
import org.mochi.libmochi.protocol.state.PreKeyStore;

public class InMemoryPreKeyStore implements PreKeyStore {

  private final Map<Integer, byte[]> store = new HashMap<>();

  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    try {
      if (!store.containsKey(preKeyId)) {
        throw new InvalidKeyIdException("No such prekeyrecord!");
      }

      return new PreKeyRecord(store.get(preKeyId));
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    store.put(preKeyId, record.serialize());
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    return store.containsKey(preKeyId);
  }

  @Override
  public void removePreKey(int preKeyId) {
    store.remove(preKeyId);
  }
}
