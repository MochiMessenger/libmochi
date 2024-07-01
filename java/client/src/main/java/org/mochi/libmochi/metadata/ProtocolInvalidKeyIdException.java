//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

import org.mochi.libmochi.metadata.protocol.UnidentifiedSenderMessageContent;

public class ProtocolInvalidKeyIdException extends ProtocolException {
  public ProtocolInvalidKeyIdException(Exception e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidKeyIdException(Exception e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
