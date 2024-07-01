#
# Copyright 2020-2022 Mochi Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

Pod::Spec.new do |s|
  s.name             = 'LibMochiClient'
  s.version          = '0.52.1'
  s.summary          = 'A Swift wrapper library for communicating with the Mochi messaging service.'

  s.homepage         = 'https://github.com/mochimessenger/libmochi'
  s.license          = 'AGPL-3.0-only'
  s.author           = 'Mochi Messenger LLC'
  s.source           = { :git => 'https://github.com/mochimessenger/libmochi.git', :tag => "v#{s.version}" }

  s.swift_version    = '5'
  s.platform         = :ios, '13.0'

  s.source_files = ['swift/Sources/**/*.swift', 'swift/Sources/**/*.m']
  s.preserve_paths = [
    'swift/Sources/MochiFfi',
    'bin/fetch_archive.py',
    'acknowledgments/acknowledgments.plist',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/MochiFfi',
      # Duplicate this here to make sure the search path is passed on to Swift dependencies.
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      'LIBMOCHI_FFI_BUILD_PATH' => 'target/$(CARGO_BUILD_TARGET)/release',
      # Store libmochi_ffi.a builds in a project-wide directory
      # because we keep simulator and device builds next to each other.
      'LIBMOCHI_FFI_TEMP_DIR' => '$(PROJECT_TEMP_DIR)/libmochi_ffi',
      'LIBMOCHI_FFI_LIB_TO_LINK' => '$(LIBMOCHI_FFI_TEMP_DIR)/$(LIBMOCHI_FFI_BUILD_PATH)/libmochi_ffi.a',

      # Make sure we link the static library, not a dynamic one.
      'OTHER_LDFLAGS' => '$(LIBMOCHI_FFI_LIB_TO_LINK)',

      'LIBMOCHI_FFI_PREBUILD_ARCHIVE' => "libmochi-client-ios-build-v#{s.version}.tar.gz",
      'LIBMOCHI_FFI_PREBUILD_CHECKSUM' => ENV.fetch('LIBMOCHI_FFI_PREBUILD_CHECKSUM', ''),

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',
      # Presently, there's no special SDK or arch for maccatalyst,
      # so we need to hackily use the "IS_MACCATALYST" build flag
      # to set the appropriate cargo target
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_' => 'aarch64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_YES' => 'aarch64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=arm64]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_ARM_$(IS_MACCATALYST))',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_' => 'x86_64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_YES' => 'x86_64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=*]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_X86_$(IS_MACCATALYST))',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.script_phases = [
    { name: 'Download libmochi-ffi if not in cache',
      execution_position: :before_compile,
      # It's not *ideal* to check the cache every build, but it's usually just a shasum.
      # It might be possible to rely on the relative mtimes of the podspec and the fetched archive,
      # but I wouldn't want to risk a mismatched archive giving us cryptic errors at link or run
      # time later. This Is Fine.
      always_out_of_date: '1',
      script: %q(
        set -euo pipefail
        if [ -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh" ]; then
          # Local development
          exit 0
        fi
        "${PODS_TARGET_SRCROOT}"/bin/fetch_archive.py -u "https://build-artifacts.mochi.org/libraries/${LIBMOCHI_FFI_PREBUILD_ARCHIVE}" -c "${LIBMOCHI_FFI_PREBUILD_CHECKSUM}" -o "${USER_LIBRARY_DIR}/Caches/org.mochi.libmochi"
      ),
    },
    { name: 'Extract libmochi-ffi prebuild',
      execution_position: :before_compile,
      input_files: ['$(USER_LIBRARY_DIR)/Caches/org.mochi.libmochi/$(LIBMOCHI_FFI_PREBUILD_ARCHIVE)'],
      output_files: ['$(LIBMOCHI_FFI_LIB_TO_LINK)'],
      script: %q(
        set -euo pipefail
        rm -rf "${LIBMOCHI_FFI_TEMP_DIR}"
        if [ -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh" ]; then
          # Local development
          ln -fns "${PODS_TARGET_SRCROOT}" "${LIBMOCHI_FFI_TEMP_DIR}"
        elif [ -e "${SCRIPT_INPUT_FILE_0}" ]; then
          mkdir -p "${LIBMOCHI_FFI_TEMP_DIR}"
          cd "${LIBMOCHI_FFI_TEMP_DIR}"
          tar -m -x -f "${SCRIPT_INPUT_FILE_0}"
        else
          echo 'error: could not download libmochi_ffi.a; please provide LIBMOCHI_FFI_PREBUILD_CHECKSUM' >&2
          exit 1
        fi
      ),
    }
  ]

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'swift/Tests/*/*.swift'
    test_spec.preserve_paths = [
      'swift/Tests/*/Resources',
    ]
    test_spec.pod_target_xcconfig = {
      # Don't also link into the test target.
      'LIBMOCHI_FFI_LIB_TO_LINK' => '',
    }

    # Ideally we'd do this at run time, not configuration time, but CocoaPods doesn't make that easy.
    # This is good enough.
    test_spec.scheme = {
      environment_variables: ENV.select { |name, value| name.start_with?('LIBMOCHI_TESTING_') }
    }
  end
end
