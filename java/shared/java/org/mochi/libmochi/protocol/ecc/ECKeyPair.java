//
// Copyright 2013-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.ecc;

public class ECKeyPair {

  private final ECPublicKey publicKey;
  private final ECPrivateKey privateKey;

  public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public ECPublicKey getPublicKey() {
    return publicKey;
  }

  public ECPrivateKey getPrivateKey() {
    return privateKey;
  }
}
