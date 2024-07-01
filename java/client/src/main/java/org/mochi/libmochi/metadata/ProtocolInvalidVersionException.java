//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

import org.mochi.libmochi.metadata.protocol.UnidentifiedSenderMessageContent;
import org.mochi.libmochi.protocol.InvalidVersionException;

public class ProtocolInvalidVersionException extends ProtocolException {
  public ProtocolInvalidVersionException(
      InvalidVersionException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidVersionException(
      InvalidVersionException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
