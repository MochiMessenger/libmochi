//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.groups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.UUID;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.MochiProtocolAddress;
import org.mochi.libmochi.protocol.groups.state.SenderKeyStore;
import org.mochi.libmochi.protocol.message.SenderKeyDistributionMessage;

/**
 * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
 *
 * <p>Once a session has been established, {@link org.mochi.libmochi.protocol.groups.GroupCipher}
 * can be used to encrypt/decrypt messages in that session.
 *
 * <p>The built sessions are unidirectional: they can be used either for sending or for receiving,
 * but not both.
 *
 * <p>Sessions are constructed per (senderName + deviceId) tuple, with sending additionally
 * parameterized on a per-group distributionId. Remote logical users are identified by their
 * senderName, and each logical user can have multiple physical devices.
 *
 * <p>This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class GroupSessionBuilder {
  private final SenderKeyStore senderKeyStore;

  public GroupSessionBuilder(SenderKeyStore senderKeyStore) {
    this.senderKeyStore = senderKeyStore;
  }

  /**
   * Construct a group session for receiving messages from sender.
   *
   * @param sender The address of the device that sent the message.
   * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
   */
  public void process(
      MochiProtocolAddress sender, SenderKeyDistributionMessage senderKeyDistributionMessage) {
    try (NativeHandleGuard senderGuard = new NativeHandleGuard(sender);
        NativeHandleGuard skdmGuard = new NativeHandleGuard(senderKeyDistributionMessage); ) {
      filterExceptions(
          () ->
              Native.GroupSessionBuilder_ProcessSenderKeyDistributionMessage(
                  senderGuard.nativeHandle(), skdmGuard.nativeHandle(), senderKeyStore));
    }
  }

  /**
   * Construct a group session for sending messages.
   *
   * @param sender The address of the current client.
   * @param distributionId An opaque identifier that uniquely identifies the group (but isn't the
   *     group ID).
   * @return A SenderKeyDistributionMessage that is individually distributed to each member of the
   *     group.
   */
  public SenderKeyDistributionMessage create(MochiProtocolAddress sender, UUID distributionId) {
    try (NativeHandleGuard senderGuard = new NativeHandleGuard(sender)) {
      return new SenderKeyDistributionMessage(
          filterExceptions(
              () ->
                  Native.GroupSessionBuilder_CreateSenderKeyDistributionMessage(
                      senderGuard.nativeHandle(), distributionId, senderKeyStore)));
    }
  }
}
