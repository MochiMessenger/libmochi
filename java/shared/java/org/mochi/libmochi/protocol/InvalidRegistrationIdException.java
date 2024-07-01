//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

public class InvalidRegistrationIdException extends Exception {

  private final MochiProtocolAddress address;

  public InvalidRegistrationIdException(MochiProtocolAddress address, String message) {
    super(message);
    this.address = address;
  }

  public MochiProtocolAddress getAddress() {
    return address;
  }
}
