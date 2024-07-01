//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.net;

import org.mochi.libmochi.internal.CompletableFuture;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;

class TokioAsyncContext extends NativeHandleGuard.SimpleOwner {
  TokioAsyncContext() {
    super(Native.TokioAsyncContext_new());
  }

  @SuppressWarnings("unchecked")
  CompletableFuture<Class<Object>> loadClassAsync(String className) {
    return (CompletableFuture<Class<Object>>) Native.AsyncLoadClass(this, className);
  }

  @Override
  protected void release(final long nativeHandle) {
    Native.TokioAsyncContext_Destroy(nativeHandle);
  }
}
