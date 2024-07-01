//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup;

public class InvalidInputException extends Exception {

  public InvalidInputException() {}

  public InvalidInputException(String message) {
    super(message);
  }
}
