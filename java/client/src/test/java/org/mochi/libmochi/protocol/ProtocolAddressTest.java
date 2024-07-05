//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.util.UUID;
import org.junit.Test;

public class ProtocolAddressTest {
  @Test
  public void testRoundTripServiceId() {
    UUID uuid = UUID.randomUUID();
    ServiceId aci = new ServiceId.Aci(uuid);
    ServiceId pni = new ServiceId.Pni(uuid);

    MochiProtocolAddress aciAddr = new MochiProtocolAddress(aci, 1);
    MochiProtocolAddress pniAddr = new MochiProtocolAddress(pni, 1);
    assertNotEquals(aciAddr, pniAddr);
    assertEquals(aci, aciAddr.getServiceId());
    assertEquals(pni, pniAddr.getServiceId());
  }
}
