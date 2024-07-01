//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.message.CiphertextMessage;
import org.mochi.libmochi.protocol.message.PreKeyMochiMessage;
import org.mochi.libmochi.protocol.message.MochiMessage;
import org.mochi.libmochi.protocol.state.IdentityKeyStore;
import org.mochi.libmochi.protocol.state.KyberPreKeyStore;
import org.mochi.libmochi.protocol.state.PreKeyStore;
import org.mochi.libmochi.protocol.state.SessionRecord;
import org.mochi.libmochi.protocol.state.SessionStore;
import org.mochi.libmochi.protocol.state.MochiProtocolStore;
import org.mochi.libmochi.protocol.state.SignedPreKeyStore;

/**
 * The main entry point for Mochi Protocol encrypt/decrypt operations.
 *
 * <p>Once a session has been established with {@link SessionBuilder}, this class can be used for
 * all encrypt/decrypt operations within that session.
 *
 * <p>This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class SessionCipher {

  private final SessionStore sessionStore;
  private final IdentityKeyStore identityKeyStore;
  private final PreKeyStore preKeyStore;
  private final SignedPreKeyStore signedPreKeyStore;
  private final KyberPreKeyStore kyberPreKeyStore;
  private final MochiProtocolAddress remoteAddress;

  /**
   * Construct a SessionCipher for encrypt/decrypt operations on a session. In order to use
   * SessionCipher, a session must have already been created and stored using {@link
   * SessionBuilder}.
   *
   * @param sessionStore The {@link SessionStore} that contains a session for this recipient.
   * @param remoteAddress The remote address that messages will be encrypted to or decrypted from.
   */
  public SessionCipher(
      SessionStore sessionStore,
      PreKeyStore preKeyStore,
      SignedPreKeyStore signedPreKeyStore,
      KyberPreKeyStore kyberPreKeyStore,
      IdentityKeyStore identityKeyStore,
      MochiProtocolAddress remoteAddress) {
    this.sessionStore = sessionStore;
    this.preKeyStore = preKeyStore;
    this.identityKeyStore = identityKeyStore;
    this.remoteAddress = remoteAddress;
    this.signedPreKeyStore = signedPreKeyStore;
    this.kyberPreKeyStore = kyberPreKeyStore;
    ;
  }

  public SessionCipher(MochiProtocolStore store, MochiProtocolAddress remoteAddress) {
    this(store, store, store, store, store, remoteAddress);
  }

  /**
   * Encrypt a message.
   *
   * @param paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   * @throws NoSessionException if there is no established session for this contact, or if an
   *     unacknowledged session has expired
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is out of date.
   */
  public CiphertextMessage encrypt(byte[] paddedMessage)
      throws NoSessionException, UntrustedIdentityException {
    return encrypt(paddedMessage, Instant.now());
  }

  /**
   * Encrypt a message.
   *
   * <p>You should only use this overload if you need to test session expiration explicitly.
   *
   * @param paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   * @throws NoSessionException if there is no established session for this contact, or if an
   *     unacknowledged session has expired
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is out of date.
   */
  public CiphertextMessage encrypt(byte[] paddedMessage, Instant now)
      throws NoSessionException, UntrustedIdentityException {
    try (NativeHandleGuard remoteAddress = new NativeHandleGuard(this.remoteAddress)) {
      return filterExceptions(
          NoSessionException.class,
          UntrustedIdentityException.class,
          () ->
              Native.SessionCipher_EncryptMessage(
                  paddedMessage,
                  remoteAddress.nativeHandle(),
                  sessionStore,
                  identityKeyStore,
                  now.toEpochMilli()));
    }
  }

  /**
   * Decrypt a message.
   *
   * @param ciphertext The {@link PreKeyMochiMessage} to decrypt.
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws InvalidKeyIdException when there is no local {@link
   *     org.mochi.libmochi.protocol.state.PreKeyRecord} that corresponds to the PreKey ID in the
   *     message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  public byte[] decrypt(PreKeyMochiMessage ciphertext)
      throws DuplicateMessageException,
          InvalidMessageException,
          InvalidKeyIdException,
          InvalidKeyException,
          UntrustedIdentityException {
    try (NativeHandleGuard ciphertextGuard = new NativeHandleGuard(ciphertext);
        NativeHandleGuard remoteAddressGuard = new NativeHandleGuard(this.remoteAddress); ) {
      return filterExceptions(
          DuplicateMessageException.class,
          InvalidMessageException.class,
          InvalidKeyIdException.class,
          InvalidKeyException.class,
          UntrustedIdentityException.class,
          () ->
              Native.SessionCipher_DecryptPreKeyMochiMessage(
                  ciphertextGuard.nativeHandle(),
                  remoteAddressGuard.nativeHandle(),
                  sessionStore,
                  identityKeyStore,
                  preKeyStore,
                  signedPreKeyStore,
                  kyberPreKeyStore));
    }
  }

  /**
   * Decrypt a message.
   *
   * @param ciphertext The {@link MochiMessage} to decrypt.
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws InvalidVersionException if the message version does not match the session version.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws NoSessionException if there is no established session for this contact.
   */
  public byte[] decrypt(MochiMessage ciphertext)
      throws InvalidMessageException,
          InvalidVersionException,
          DuplicateMessageException,
          NoSessionException,
          UntrustedIdentityException {
    try (NativeHandleGuard ciphertextGuard = new NativeHandleGuard(ciphertext);
        NativeHandleGuard remoteAddressGuard = new NativeHandleGuard(this.remoteAddress); ) {
      return filterExceptions(
          InvalidMessageException.class,
          InvalidVersionException.class,
          DuplicateMessageException.class,
          NoSessionException.class,
          UntrustedIdentityException.class,
          () ->
              Native.SessionCipher_DecryptMochiMessage(
                  ciphertextGuard.nativeHandle(),
                  remoteAddressGuard.nativeHandle(),
                  sessionStore,
                  identityKeyStore));
    }
  }

  public int getRemoteRegistrationId() {
    if (!sessionStore.containsSession(remoteAddress)) {
      throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
    }

    SessionRecord record = sessionStore.loadSession(remoteAddress);
    return record.getRemoteRegistrationId();
  }

  public int getSessionVersion() {
    if (!sessionStore.containsSession(remoteAddress)) {
      throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
    }

    SessionRecord record = sessionStore.loadSession(remoteAddress);
    return record.getSessionVersion();
  }
}
