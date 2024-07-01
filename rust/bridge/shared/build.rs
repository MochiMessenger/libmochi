//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    // Set environment variables for bridge_fn to produce correctly-named symbols for FFI and JNI.
    println!("cargo:rustc-env=LIBMOCHI_BRIDGE_FN_PREFIX_FFI=mochi_");
    // This naming convention comes from JNI:
    // https://docs.oracle.com/en/java/javase/20/docs/specs/jni/design.html#resolving-native-method-names
    println!(
        "cargo:rustc-env=LIBMOCHI_BRIDGE_FN_PREFIX_JNI=Java_org_mochi_libmochi_internal_Native_"
    );
}
