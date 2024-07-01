//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

/** Indicates that the local device has been deregistered or delinked. */
public class DeviceDeregisteredException extends ChatServiceException {
  public DeviceDeregisteredException(String message) {
    super(message);
  }
}
