//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata;

public class InvalidMetadataMessageException extends Exception {
  public InvalidMetadataMessageException(String s) {
    super(s);
  }

  public InvalidMetadataMessageException(Exception s) {
    super(s);
  }
}
