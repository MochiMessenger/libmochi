//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state.impl;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.NoSessionException;
import org.mochi.libmochi.protocol.MochiProtocolAddress;
import org.mochi.libmochi.protocol.state.SessionRecord;
import org.mochi.libmochi.protocol.state.SessionStore;

public class InMemorySessionStore implements SessionStore {

  private Map<MochiProtocolAddress, byte[]> sessions = new HashMap<>();

  public InMemorySessionStore() {}

  @Override
  public synchronized SessionRecord loadSession(MochiProtocolAddress remoteAddress) {
    try {
      if (containsSession(remoteAddress)) {
        return new SessionRecord(sessions.get(remoteAddress));
      } else {
        return null;
      }
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public synchronized List<SessionRecord> loadExistingSessions(
      List<MochiProtocolAddress> addresses) throws NoSessionException {
    List<SessionRecord> resultSessions = new LinkedList<>();
    for (MochiProtocolAddress remoteAddress : addresses) {
      byte[] serialized = sessions.get(remoteAddress);
      if (serialized == null) {
        throw new NoSessionException(remoteAddress, "no session for " + remoteAddress);
      }
      try {
        resultSessions.add(new SessionRecord(serialized));
      } catch (InvalidMessageException e) {
        throw new AssertionError(e);
      }
    }
    return resultSessions;
  }

  @Override
  public synchronized List<Integer> getSubDeviceSessions(String name) {
    List<Integer> deviceIds = new LinkedList<>();

    for (MochiProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name) && key.getDeviceId() != 1) {
        deviceIds.add(key.getDeviceId());
      }
    }

    return deviceIds;
  }

  @Override
  public synchronized void storeSession(MochiProtocolAddress address, SessionRecord record) {
    sessions.put(address, record.serialize());
  }

  @Override
  public synchronized boolean containsSession(MochiProtocolAddress address) {
    return sessions.containsKey(address);
  }

  @Override
  public synchronized void deleteSession(MochiProtocolAddress address) {
    sessions.remove(address);
  }

  @Override
  public synchronized void deleteAllSessions(String name) {
    for (MochiProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name)) {
        sessions.remove(key);
      }
    }
  }
}
