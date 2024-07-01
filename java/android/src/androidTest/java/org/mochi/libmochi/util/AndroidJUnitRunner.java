//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.util;

import android.os.Bundle;
import org.mochi.libmochi.protocol.logging.AndroidMochiProtocolLogger;
import org.mochi.libmochi.protocol.logging.MochiProtocolLogger;
import org.mochi.libmochi.protocol.logging.MochiProtocolLoggerProvider;

/** Custom setup for our JUnit tests, when run as instrumentation tests. */
public class AndroidJUnitRunner extends androidx.test.runner.AndroidJUnitRunner {
  @Override
  public void onCreate(Bundle bundle) {
    super.onCreate(bundle);

    // Make sure libmochi logs get caught correctly.
    MochiProtocolLoggerProvider.setProvider(new AndroidMochiProtocolLogger());
    MochiProtocolLoggerProvider.initializeLogging(MochiProtocolLogger.VERBOSE);

    // Propagate any "environment variables" the test might need into System properties.
    String testEnvironment = bundle.getString(TestEnvironment.PROPERTY_NAMESPACE);
    if (testEnvironment != null) {
      for (String joinedProp : testEnvironment.split(",")) {
        String[] splitProp = joinedProp.split("=", 2);
        if (splitProp.length != 2) {
          continue;
        }
        System.setProperty(TestEnvironment.PROPERTY_NAMESPACE + "." + splitProp[0], splitProp[1]);
      }
    }
  }
}
