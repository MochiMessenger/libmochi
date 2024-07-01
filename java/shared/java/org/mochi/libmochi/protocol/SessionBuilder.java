//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.state.IdentityKeyStore;
import org.mochi.libmochi.protocol.state.PreKeyBundle;
import org.mochi.libmochi.protocol.state.PreKeyStore;
import org.mochi.libmochi.protocol.state.SessionStore;
import org.mochi.libmochi.protocol.state.MochiProtocolStore;
import org.mochi.libmochi.protocol.state.SignedPreKeyStore;

/**
 * SessionBuilder is responsible for setting up encrypted sessions. Once a session has been
 * established, {@link org.mochi.libmochi.protocol.SessionCipher} can be used to encrypt/decrypt
 * messages in that session.
 *
 * <p>Sessions are built from one of two different possible vectors:
 *
 * <ol>
 *   <li>A {@link org.mochi.libmochi.protocol.state.PreKeyBundle} retrieved from a server.
 *   <li>A {@link org.mochi.libmochi.protocol.message.PreKeyMochiMessage} received from a client.
 * </ol>
 *
 * Only the first, however, is handled by SessionBuilder.
 *
 * <p>Sessions are constructed per recipientId + deviceId tuple. Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * <p>This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class SessionBuilder {
  private static final String TAG = SessionBuilder.class.getSimpleName();

  private final SessionStore sessionStore;
  private final PreKeyStore preKeyStore;
  private final SignedPreKeyStore signedPreKeyStore;
  private final IdentityKeyStore identityKeyStore;
  private final MochiProtocolAddress remoteAddress;

  /**
   * Constructs a SessionBuilder.
   *
   * @param sessionStore The {@link org.mochi.libmochi.protocol.state.SessionStore} to store the
   *     constructed session in.
   * @param preKeyStore The {@link org.mochi.libmochi.protocol.state.PreKeyStore} where the
   *     client's local {@link org.mochi.libmochi.protocol.state.PreKeyRecord}s are stored.
   * @param identityKeyStore The {@link org.mochi.libmochi.protocol.state.IdentityKeyStore}
   *     containing the client's identity key information.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  public SessionBuilder(
      SessionStore sessionStore,
      PreKeyStore preKeyStore,
      SignedPreKeyStore signedPreKeyStore,
      IdentityKeyStore identityKeyStore,
      MochiProtocolAddress remoteAddress) {
    this.sessionStore = sessionStore;
    this.preKeyStore = preKeyStore;
    this.signedPreKeyStore = signedPreKeyStore;
    this.identityKeyStore = identityKeyStore;
    this.remoteAddress = remoteAddress;
  }

  /**
   * Constructs a SessionBuilder
   *
   * @param store The {@link MochiProtocolStore} to store all state information in.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  public SessionBuilder(MochiProtocolStore store, MochiProtocolAddress remoteAddress) {
    this(store, store, store, store, remoteAddress);
  }

  /**
   * Build a new session from a {@link org.mochi.libmochi.protocol.state.PreKeyBundle} retrieved
   * from a server.
   *
   * @param preKey A PreKey for the destination recipient, retrieved from a server.
   * @throws InvalidKeyException when the {@link org.mochi.libmochi.protocol.state.PreKeyBundle}
   *     is badly formatted.
   * @throws org.mochi.libmochi.protocol.UntrustedIdentityException when the sender's {@link
   *     IdentityKey} is not trusted.
   */
  public void process(PreKeyBundle preKey) throws InvalidKeyException, UntrustedIdentityException {
    process(preKey, Instant.now());
  }

  /**
   * Build a new session from a {@link org.mochi.libmochi.protocol.state.PreKeyBundle} retrieved
   * from a server.
   *
   * <p>You should only use this overload if you need to test session expiration explicitly.
   *
   * @param preKey A PreKey for the destination recipient, retrieved from a server.
   * @param now The current time, used later to check if the session is stale.
   * @throws InvalidKeyException when the {@link org.mochi.libmochi.protocol.state.PreKeyBundle}
   *     is badly formatted.
   * @throws org.mochi.libmochi.protocol.UntrustedIdentityException when the sender's {@link
   *     IdentityKey} is not trusted.
   */
  public void process(PreKeyBundle preKey, Instant now)
      throws InvalidKeyException, UntrustedIdentityException {
    try (NativeHandleGuard preKeyGuard = new NativeHandleGuard(preKey);
        NativeHandleGuard remoteAddressGuard = new NativeHandleGuard(this.remoteAddress)) {
      filterExceptions(
          InvalidKeyException.class,
          UntrustedIdentityException.class,
          () ->
              Native.SessionBuilder_ProcessPreKeyBundle(
                  preKeyGuard.nativeHandle(),
                  remoteAddressGuard.nativeHandle(),
                  sessionStore,
                  identityKeyStore,
                  now.toEpochMilli()));
    }
  }
}
