//
// Copyright 2021-2022 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.devicetransfer;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import junit.framework.TestCase;

public class DeviceTransferKeyTest extends TestCase {
  public void testDeviceTransferKey() throws Exception {
    DeviceTransferKey key = new DeviceTransferKey();
    byte[] certBytes = key.generateCertificate("name", 365);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    cf.generateCertificate(new ByteArrayInputStream(certBytes));
  }
}
