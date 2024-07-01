//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.groups;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.util.UUID;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.DuplicateMessageException;
import org.mochi.libmochi.protocol.InvalidMessageException;
import org.mochi.libmochi.protocol.LegacyMessageException;
import org.mochi.libmochi.protocol.NoSessionException;
import org.mochi.libmochi.protocol.MochiProtocolAddress;
import org.mochi.libmochi.protocol.groups.state.SenderKeyStore;
import org.mochi.libmochi.protocol.message.CiphertextMessage;

/**
 * The main entry point for Mochi Protocol group encrypt/decrypt operations.
 *
 * <p>Once a session has been established with {@link
 * org.mochi.libmochi.protocol.groups.GroupSessionBuilder} and a {@link
 * org.mochi.libmochi.protocol.message.SenderKeyDistributionMessage} has been distributed to each
 * member of the group, this class can be used for all subsequent encrypt/decrypt operations within
 * that session (ie: until group membership changes).
 *
 * <p>This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class GroupCipher {

  private final SenderKeyStore senderKeyStore;
  private final MochiProtocolAddress sender;

  public GroupCipher(SenderKeyStore senderKeyStore, MochiProtocolAddress sender) {
    this.senderKeyStore = senderKeyStore;
    this.sender = sender;
  }

  /**
   * Encrypt a message.
   *
   * @param paddedPlaintext The plaintext message bytes, optionally padded.
   * @return Ciphertext.
   * @throws NoSessionException
   */
  public CiphertextMessage encrypt(UUID distributionId, byte[] paddedPlaintext)
      throws NoSessionException {
    try (NativeHandleGuard sender = new NativeHandleGuard(this.sender)) {
      return filterExceptions(
          NoSessionException.class,
          () ->
              Native.GroupCipher_EncryptMessage(
                  sender.nativeHandle(), distributionId, paddedPlaintext, this.senderKeyStore));
    }
  }

  /**
   * Decrypt a SenderKey group message.
   *
   * @param senderKeyMessageBytes The received ciphertext.
   * @return Plaintext
   * @throws LegacyMessageException
   * @throws InvalidMessageException
   * @throws DuplicateMessageException
   */
  public byte[] decrypt(byte[] senderKeyMessageBytes)
      throws LegacyMessageException,
          DuplicateMessageException,
          InvalidMessageException,
          NoSessionException {
    try (NativeHandleGuard sender = new NativeHandleGuard(this.sender)) {
      return filterExceptions(
          LegacyMessageException.class,
          DuplicateMessageException.class,
          InvalidMessageException.class,
          NoSessionException.class,
          () ->
              Native.GroupCipher_DecryptMessage(
                  sender.nativeHandle(), senderKeyMessageBytes, this.senderKeyStore));
    }
  }
}
