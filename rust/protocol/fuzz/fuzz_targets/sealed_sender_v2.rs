//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use libfuzzer_sys::fuzz_target;
use libmochi_protocol::*;

fuzz_target!(|data: &[u8]| {
    let _: Result<_, _> = SealedSenderV2SentMessage::parse(data);
});
