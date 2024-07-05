//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.util;

import org.mochi.libmochi.protocol.logging.MochiProtocolLogger;

public class StderrLogger implements MochiProtocolLogger {
  @Override
  public void log(int priority, String tag, String message) {
    String prefix;
    switch (priority) {
      case MochiProtocolLogger.VERBOSE:
        prefix = "V ";
        break;
      case MochiProtocolLogger.DEBUG:
        prefix = "D ";
        break;
      case MochiProtocolLogger.INFO:
        prefix = "I ";
        break;
      case MochiProtocolLogger.WARN:
        prefix = "W ";
        break;
      case MochiProtocolLogger.ERROR:
        prefix = "E ";
        break;
      case MochiProtocolLogger.ASSERT:
        prefix = "A ";
        break;
      default:
        prefix = "";
        break;
    }
    System.err.println(prefix + tag + ": " + message);
  }
}
