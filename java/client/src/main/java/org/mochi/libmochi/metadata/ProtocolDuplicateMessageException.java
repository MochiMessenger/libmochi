//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

import org.mochi.libmochi.metadata.protocol.UnidentifiedSenderMessageContent;

public class ProtocolDuplicateMessageException extends ProtocolException {
  public ProtocolDuplicateMessageException(Exception e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolDuplicateMessageException(Exception e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
