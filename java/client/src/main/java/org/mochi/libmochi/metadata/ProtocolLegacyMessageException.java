//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

import org.mochi.libmochi.metadata.protocol.UnidentifiedSenderMessageContent;
import org.mochi.libmochi.protocol.LegacyMessageException;

public class ProtocolLegacyMessageException extends ProtocolException {
  public ProtocolLegacyMessageException(
      LegacyMessageException e, String sender, int senderDeviceId) {
    super(e, sender, senderDeviceId);
  }

  ProtocolLegacyMessageException(
      LegacyMessageException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
