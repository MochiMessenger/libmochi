//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.logging;

import android.util.Log;
import android.util.SparseIntArray;

public class AndroidMochiProtocolLogger implements MochiProtocolLogger {

  private static final SparseIntArray PRIORITY_MAP =
      new SparseIntArray(5) {
        {
          put(MochiProtocolLogger.INFO, Log.INFO);
          put(MochiProtocolLogger.ASSERT, Log.ASSERT);
          put(MochiProtocolLogger.DEBUG, Log.DEBUG);
          put(MochiProtocolLogger.VERBOSE, Log.VERBOSE);
          put(MochiProtocolLogger.WARN, Log.WARN);
        }
      };

  @Override
  public void log(int priority, String tag, String message) {
    int androidPriority = PRIORITY_MAP.get(priority, Log.WARN);
    Log.println(androidPriority, tag, message);
  }
}
