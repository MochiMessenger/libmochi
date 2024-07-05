//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import junit.framework.TestCase;

public class IdentityKeyTest extends TestCase {
  public void testMochiternateKey() {
    IdentityKeyPair primary = IdentityKeyPair.generate();
    IdentityKeyPair secondary = IdentityKeyPair.generate();
    byte[] signature = secondary.mochiternateIdentity(primary.getPublicKey());
    assertTrue(secondary.getPublicKey().verifyAlternateIdentity(primary.getPublicKey(), signature));
  }
}
