//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

import org.mochi.libmochi.metadata.protocol.UnidentifiedSenderMessageContent;
import org.mochi.libmochi.protocol.InvalidMessageException;

public class ProtocolInvalidMessageException extends ProtocolException {
  public ProtocolInvalidMessageException(
      InvalidMessageException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidMessageException(
      InvalidMessageException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
