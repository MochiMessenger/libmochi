//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import java.util.Random;
import org.mochi.libmochi.protocol.ecc.Curve;
import org.mochi.libmochi.protocol.ecc.ECKeyPair;
import org.mochi.libmochi.protocol.state.PreKeyBundle;
import org.mochi.libmochi.protocol.state.PreKeyRecord;
import org.mochi.libmochi.protocol.state.MochiProtocolStore;
import org.mochi.libmochi.protocol.state.SignedPreKeyRecord;
import org.mochi.libmochi.protocol.util.Medium;

public final class X3DHBundleFactory implements BundleFactory {
  @Override
  public PreKeyBundle createBundle(MochiProtocolStore store) throws InvalidKeyException {
    ECKeyPair preKeyPair = Curve.generateKeyPair();
    ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
    byte[] signedPreKeySignature =
        Curve.calculateSignature(
            store.getIdentityKeyPair().getPrivateKey(),
            signedPreKeyPair.getPublicKey().serialize());
    Random random = new Random();
    int preKeyId = random.nextInt(Medium.MAX_VALUE);
    int signedPreKeyId = random.nextInt(Medium.MAX_VALUE);
    store.storePreKey(preKeyId, new PreKeyRecord(preKeyId, preKeyPair));
    store.storeSignedPreKey(
        signedPreKeyId,
        new SignedPreKeyRecord(
            signedPreKeyId, System.currentTimeMillis(), signedPreKeyPair, signedPreKeySignature));

    return new PreKeyBundle(
        store.getLocalRegistrationId(),
        1,
        preKeyId,
        preKeyPair.getPublicKey(),
        signedPreKeyId,
        signedPreKeyPair.getPublicKey(),
        signedPreKeySignature,
        store.getIdentityKeyPair().getPublicKey());
  }
}
