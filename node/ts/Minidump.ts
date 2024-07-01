//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native';

export function toJSONString(buffer: Buffer): string {
  return Native.MinidumpToJSONString(buffer);
}
