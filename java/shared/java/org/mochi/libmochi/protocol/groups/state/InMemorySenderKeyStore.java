//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.groups.state;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.MochiProtocolAddress;
import org.mochi.libmochi.protocol.util.Pair;

public class InMemorySenderKeyStore implements SenderKeyStore {

  private final Map<Pair<MochiProtocolAddress, UUID>, SenderKeyRecord> store = new HashMap<>();

  @Override
  public void storeSenderKey(
      MochiProtocolAddress sender, UUID distributionId, SenderKeyRecord record) {
    store.put(new Pair<>(sender, distributionId), record);
  }

  @Override
  public SenderKeyRecord loadSenderKey(MochiProtocolAddress sender, UUID distributionId) {
    try {
      SenderKeyRecord record = store.get(new Pair<>(sender, distributionId));

      if (record == null) {
        return null;
      } else {
        return new SenderKeyRecord(record.serialize());
      }
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }
}
