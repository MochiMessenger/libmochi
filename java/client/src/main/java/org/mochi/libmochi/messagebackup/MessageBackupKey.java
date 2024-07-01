//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.messagebackup;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.ServiceId.Aci;

public class MessageBackupKey implements NativeHandleGuard.Owner {

  public MessageBackupKey(byte[] masterKey, Aci aci) {
    this.nativeHandle = Native.MessageBackupKey_New(masterKey, aci.toServiceIdFixedWidthBinary());
  }

  @Override
  public long unsafeNativeHandleWithoutGuard() {
    return nativeHandle;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.MessageBackupKey_Destroy(this.nativeHandle);
  }

  private long nativeHandle;
}
