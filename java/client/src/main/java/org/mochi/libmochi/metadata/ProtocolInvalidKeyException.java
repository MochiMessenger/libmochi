//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

import org.mochi.libmochi.metadata.protocol.UnidentifiedSenderMessageContent;
import org.mochi.libmochi.protocol.InvalidKeyException;

public class ProtocolInvalidKeyException extends ProtocolException {
  public ProtocolInvalidKeyException(InvalidKeyException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidKeyException(InvalidKeyException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
