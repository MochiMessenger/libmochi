//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.logging;

import org.mochi.libmochi.internal.Native;

public class MochiProtocolLoggerProvider {

  private static MochiProtocolLogger provider;

  /**
   * Enables logging from libmochi's native code.
   *
   * <p>Should only be called once; later calls will be ignored.
   *
   * @param maxLevel The most severe level that should be logged. Should be one of the constants
   *     from {@link MochiProtocolLogger}. In a normal release build, this is clamped to {@code
   *     INFO}.
   */
  public static void initializeLogging(int maxLevel) {
    if (maxLevel < MochiProtocolLogger.VERBOSE || maxLevel > MochiProtocolLogger.ASSERT) {
      throw new IllegalArgumentException("invalid log level");
    }
    Native.Logger_Initialize(maxLevel, Log.class);
  }

  public static MochiProtocolLogger getProvider() {
    return provider;
  }

  public static void setProvider(MochiProtocolLogger provider) {
    MochiProtocolLoggerProvider.provider = provider;
  }
}
