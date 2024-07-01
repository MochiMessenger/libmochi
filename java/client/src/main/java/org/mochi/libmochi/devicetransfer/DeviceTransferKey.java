//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.devicetransfer;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;

import org.mochi.libmochi.internal.Native;

public class DeviceTransferKey {
  byte[] keyMaterial;

  public DeviceTransferKey() {
    this.keyMaterial = Native.DeviceTransfer_GeneratePrivateKey();
  }

  public byte[] keyMaterial() {
    return this.keyMaterial;
  }

  public byte[] generateCertificate(String name, int daysTilExpires) {
    return filterExceptions(
        () -> Native.DeviceTransfer_GenerateCertificate(this.keyMaterial, name, daysTilExpires));
  }
}
