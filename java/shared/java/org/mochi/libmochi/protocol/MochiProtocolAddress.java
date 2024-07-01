//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;

public class MochiProtocolAddress implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public MochiProtocolAddress(String name, int deviceId) {
    this.unsafeHandle = Native.ProtocolAddress_New(name, deviceId);
  }

  public MochiProtocolAddress(ServiceId serviceId, int deviceId) {
    this(serviceId.toServiceIdString(), deviceId);
  }

  public MochiProtocolAddress(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.ProtocolAddress_Destroy(this.unsafeHandle);
  }

  public String getName() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ProtocolAddress_Name(guard.nativeHandle());
    }
  }

  /**
   * Returns a ServiceId if this address contains a valid ServiceId, {@code null} otherwise.
   *
   * <p>In a future release MochiProtocolAddresses will <em>only</em> support ServiceIds.
   */
  public ServiceId getServiceId() {
    try {
      return ServiceId.parseFromString(getName());
    } catch (ServiceId.InvalidServiceIdException e) {
      return null;
    }
  }

  public int getDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ProtocolAddress_DeviceId(guard.nativeHandle());
    }
  }

  @Override
  public String toString() {
    return getName() + "." + getDeviceId();
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) return false;
    if (!(other instanceof MochiProtocolAddress)) return false;

    MochiProtocolAddress that = (MochiProtocolAddress) other;
    return this.getName().equals(that.getName()) && this.getDeviceId() == that.getDeviceId();
  }

  @Override
  public int hashCode() {
    return this.getName().hashCode() ^ this.getDeviceId();
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
