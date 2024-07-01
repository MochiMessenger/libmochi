//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

/** The order of values in this enum should match {@code IpType} enum in Rust (libmochi-net). */
public enum IpType {
  UNKNOWN,
  IPv4,
  IPv6
}
