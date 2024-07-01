//
// Copyright 2014-2016 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.protocol.logging;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.UnknownHostException;
import org.mochi.libmochi.internal.CalledFromNative;

public class Log {

  private Log() {}

  public static void v(String tag, String msg) {
    log(MochiProtocolLogger.VERBOSE, tag, msg);
  }

  public static void v(String tag, String msg, Throwable tr) {
    log(MochiProtocolLogger.VERBOSE, tag, msg + '\n' + getStackTraceString(tr));
  }

  public static void d(String tag, String msg) {
    log(MochiProtocolLogger.DEBUG, tag, msg);
  }

  public static void d(String tag, String msg, Throwable tr) {
    log(MochiProtocolLogger.DEBUG, tag, msg + '\n' + getStackTraceString(tr));
  }

  public static void i(String tag, String msg) {
    log(MochiProtocolLogger.INFO, tag, msg);
  }

  public static void i(String tag, String msg, Throwable tr) {
    log(MochiProtocolLogger.INFO, tag, msg + '\n' + getStackTraceString(tr));
  }

  public static void w(String tag, String msg) {
    log(MochiProtocolLogger.WARN, tag, msg);
  }

  public static void w(String tag, String msg, Throwable tr) {
    log(MochiProtocolLogger.WARN, tag, msg + '\n' + getStackTraceString(tr));
  }

  public static void w(String tag, Throwable tr) {
    log(MochiProtocolLogger.WARN, tag, getStackTraceString(tr));
  }

  public static void e(String tag, String msg) {
    log(MochiProtocolLogger.ERROR, tag, msg);
  }

  public static void e(String tag, String msg, Throwable tr) {
    log(MochiProtocolLogger.ERROR, tag, msg + '\n' + getStackTraceString(tr));
  }

  private static String getStackTraceString(Throwable tr) {
    if (tr == null) {
      return "";
    }

    // This is to reduce the amount of log spew that apps do in the non-error
    // condition of the network being unavailable.
    Throwable t = tr;
    while (t != null) {
      if (t instanceof UnknownHostException) {
        return "";
      }
      t = t.getCause();
    }

    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    tr.printStackTrace(pw);
    pw.flush();
    return sw.toString();
  }

  @CalledFromNative
  private static void log(int priority, String tag, String msg) {
    MochiProtocolLogger logger = MochiProtocolLoggerProvider.getProvider();

    if (logger != null) {
      logger.log(priority, tag, msg);
    }
  }
}
