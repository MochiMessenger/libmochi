//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol;

import org.mochi.libmochi.protocol.state.PreKeyBundle;
import org.mochi.libmochi.protocol.state.MochiProtocolStore;

public interface BundleFactory {
  PreKeyBundle createBundle(MochiProtocolStore store) throws InvalidKeyException;
}
