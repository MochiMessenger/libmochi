//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

public class NoSessionException extends Exception {
  private final MochiProtocolAddress address;

  public NoSessionException(String message) {
    this(null, message);
  }

  public NoSessionException(MochiProtocolAddress address, String message) {
    super(message);
    this.address = address;
  }

  public MochiProtocolAddress getAddress() {
    return address;
  }
}
