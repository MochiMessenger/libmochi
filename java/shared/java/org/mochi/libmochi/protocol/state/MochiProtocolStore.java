//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.state;

import org.mochi.libmochi.protocol.groups.state.SenderKeyStore;

public interface MochiProtocolStore
    extends IdentityKeyStore,
        PreKeyStore,
        SessionStore,
        SignedPreKeyStore,
        SenderKeyStore,
        KyberPreKeyStore {}
