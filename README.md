# Overview

libmochi contains platform-agnostic APIs used by the official Mochi clients and servers, exposed
as a Java, Swift, or TypeScript library. The underlying implementations are written in Rust:

- libmochi-protocol: Implements the Mochi protocol, including the [Double Ratchet algorithm][]. A
  replacement for [libmochi-protocol-java][] and [libmochi-metadata-java][].
- mochi-crypto: Cryptographic primitives such as AES-GCM. We use [RustCrypto][]'s where we can
  but sometimes have differing needs.
- device-transfer: Support logic for Mochi's device-to-device transfer feature.
- attest: Functionality for remote attestation of [SGX enclaves][] and server-side [HSMs][].
- zkgroup: Functionality for [zero-knowledge groups][] and related features available in Mochi.
- zkcredential: An abstraction for the sort of zero-knowledge credentials used by zkgroup, based on the paper "[The Mochi Private Group System][]" by Chase, Perrin, and Zaverucha.
- poksho: Utilities for implementing zero-knowledge proofs (such as those used by zkgroup); stands for "proof-of-knowledge, stateful-hash-object".
- pin: Functionality for consistently using [PINs][] as passwords in Mochi's Secure Value Recovery system.
- usernames: Functionality for username generation, hashing, and proofs.
- media: Utilities for manipulating media.

This repository is used by the Mochi client apps ([Android][], [iOS][], and [Desktop][]) as well as
server-side. Use outside of Mochi is unsupported. In particular, the products of this repository
are the Java, Swift, and TypeScript libraries that wrap the underlying Rust implementations. All
APIs and implementations are subject to change without notice, as are the JNI, C, and Node add-on
"bridge" layers. However, backwards-incompatible changes to the Java, Swift, TypeScript, and
non-bridge Rust APIs will be reflected in the version number on a best-effort basis, including
increases to the minimum supported tools versions.

[Double Ratchet algorithm]: https://mochi.org/docs/
[libmochi-protocol-java]: https://github.com/mochimessenger/libmochi-protocol-java
[libmochi-metadata-java]: https://github.com/mochimessenger/libmochi-metadata-java
[RustCrypto]: https://github.com/RustCrypto
[Noise protocol]: http://noiseprotocol.org/
[SGX enclaves]: https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html
[HSMs]: https://en.wikipedia.org/wiki/Hardware_security_module
[zero-knowledge groups]: https://mochi.org/blog/mochi-private-group-system/
[The Mochi Private Group System]: https://eprint.iacr.org/2019/1416.pdf
[PINs]: https://mochi.org/blog/mochi-pins/
[Android]: https://github.com/mochimessenger/Mochi-Android
[iOS]: https://github.com/mochimessenger/Mochi-iOS
[Desktop]: https://github.com/mochimessenger/Mochi-Desktop


# Building

To build anything in this repository you must have [Rust](https://rust-lang.org) installed,
as well as Clang, libclang, [CMake](https://cmake.org), Make, protoc, and git.
On a Debian-like system, you can get these extra dependencies through `apt`:

```shell
$ apt-get install clang libclang-dev cmake make protobuf-compiler git
```

The build currently uses a specific version of the Rust nightly compiler, which
will be downloaded automatically by cargo. To build and test the basic protocol
libraries:

```shell
$ cargo build
...
$ cargo test
...
```

## Java/Android

To build for Android you must install several additional packages including a JDK,
the Android NDK/SDK, and add the Android targets to the Rust compiler, using

```rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android```

To build the Java/Android ``jar`` and ``aar``, and run the tests:

```shell
$ cd java
$ ./gradlew test
$ ./gradlew build # if you need AAR outputs
```

You can pass `-P debugLevelLogs` to Gradle to build without filtering out debug- and verbose-level
logs from Rust.

Alternately, a build system using Docker is available:

```shell
$ cd java
$ make
```

When exposing new APIs to Java, you will need to run `rust/bridge/jni/bin/gen_java_decl.py` in
addition to rebuilding.

### Maven Central

Mochi publishes Java packages on [Maven Central](https://central.sonatype.org) for its own use,
under the names org.mochi:libmochi-server, org.mochi:libmochi-client, and
org.mochi:libmochi-android. libmochi-client and libmochi-server contain native libraries for
Debian-flavored x86_64 Linux as well as Windows (x86_64) and macOS (x86_64 and arm64).
libmochi-android contains native libraries for armeabi-v7a, arm64-v8a, x86, and x86_64 Android.

When building for Android you need *both* libmochi-android and libmochi-client, but the Windows
and macOS libraries in libmochi-client won't automatically be excluded from your final app. You can
explicitly exclude them using `packagingOptions`:

```
android {
  // ...
  packagingOptions {
    resources {
      exclude "libmochi_jni.dylib"
      exclude "mochi_jni.dll"
    }
  }
  // ...
}
```


## Swift

To learn about the Swift build process see [``swift/README.md``](swift/)


## Node

You'll need Node installed to build. If you have [nvm][], you can run `nvm use` to select an
appropriate version automatically.

We use [`yarn`](https://classic.yarnpkg.com/) as our package manager. The Rust library will automatically be built when you run `yarn install`.

```shell
$ cd node
$ nvm use
$ yarn install
$ yarn tsc
$ yarn test
```

When testing changes locally, you can use `yarn build` to do an incremental rebuild of the Rust library. Alternately, `yarn build-with-debug-level-logs` will rebuild without filtering out debug- and verbose-level logs.

When exposing new APIs to Node, you will need to run `rust/bridge/node/bin/gen_ts_decl.py` in
addition to rebuilding.

[nvm]: https://github.com/nvm-sh/nvm

### NPM

Mochi publishes the NPM package `@mochimessenger/libmochi-client` for its own use, including native
libraries for Windows, macOS, and Debian-flavored Linux. Both x64 and arm64 builds are included for
all three platforms, but the arm64 builds for Windows and Linux are considered experimental, since
there are no official builds of Mochi for those architectures.


# Contributions

Mochi does accept external contributions to this project. However unless the change is
simple and easily understood, for example fixing a bug or portability issue, adding a new
test, or improving performance, first open an issue to discuss your intended change as not
all changes can be accepted.

Contributions that will not be used directly by one of Mochi's official client apps may still be
considered, but only if they do not pose an undue maintenance burden or conflict with the goals of
the project.

Signing a [CLA (Contributor License Agreement)](https://mochi.org/cla/) is required for all contributions.

# Legal things
## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on
the import, possession, use, and/or re-export to another country, of encryption software.  BEFORE using any encryption
software, please check your country's laws, regulations and policies concerning the import, possession, or use, and
re-export of encryption software, to see if this is permitted.  See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as
Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing
cryptographic functions with asymmetric algorithms.  The form and manner of this distribution makes it eligible for
export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and source code.

## License

Copyright 2020-2024 Mochi Messenger, LLC

Licensed under the GNU AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
