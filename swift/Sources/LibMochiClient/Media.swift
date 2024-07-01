//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#if MOCHI_MEDIA_SUPPORTED

import Foundation
import MochiFfi

/// "Sanitize" an MP4 input.
///
/// Currently the sanitizer always performs the following functions:
///
/// - Return all presentation metadata present in the input as a self-contained contiguous byte array.
/// - Find and return a pointer to the span in the input containing the (contiguous) media data.
///
/// “Presentation” metadata means any metadata which is required by an MP4 player to play the file. “Self-contained and
/// contiguous” means that the returned metadata can be concatenated with the media data to form a valid MP4 file.
///
/// The original metadata may or may not need to be modified in order to perform these functions. In the case that the
/// original metadata does not need to be modified, the returned sanitized metadata will be null to prevent needless data
/// copying.
///
/// ## Unsupported MP4 features
///
/// The sanitizer does not currently support:
///
/// - “Fragmented” MP4 files, which are mostly used for adaptive-bitrate streaming.
/// - Discontiguous media data, i.e. media data (mdat) boxes interspersed with presentation metadata (moov).
/// - Media data references (dref) pointing to separate files.
/// - Any similar format, e.g. Quicktime File Format (mov) or the legacy MP4 version 1, which does not contain the "isom"
///   compatible brand in its file type header (ftyp).
///
/// - Parameters:
///  - input: An MP4 format input stream.
///  - length: The exact length of the input stream.
///
/// - Returns: The sanitized metadata.
///
/// - Throws:
///  - `MochiError.ioError`: If an IO error on the input occurs.
///  - `MochiError.invalidMediaInput` If the input could not be parsed because it was invalid.
///  - `MochiError.unsupportedMediaInput` If the input could not be parsed because it's unsupported in some way.
public func sanitizeMp4(input: MochiInputStream, len: UInt64) throws -> SanitizedMetadata {
    return try withInputStream(input) { ffiInput in
        try invokeFnReturningNativeHandle {
            mochi_mp4_sanitizer_sanitize($0, ffiInput, len)
        }
    }
}

/// "Sanitize" a WebP input.
///
/// The sanitizer currently simply checks the validity of a WebP file input, so that passing a malformed file to an
/// unsafe parser can be avoided.
///
/// - Parameters:
///  - input: A WebP format input stream.
///
/// - Throws:
///  - `MochiError.ioError`: If an IO error on the input occurs.
///  - `MochiError.invalidMediaInput` If the input could not be parsed because it was invalid.
///  - `MochiError.unsupportedMediaInput` If the input could not be parsed because it's unsupported in some way.
public func sanitizeWebp(input: MochiInputStream) throws {
    try withInputStream(input) { ffiInput in
        try checkError(mochi_webp_sanitizer_sanitize(ffiInput))
    }
}

@available(*, deprecated, message: "Prefer the version without a length; it is now ignored")
public func sanitizeWebp(input: MochiInputStream, length ignored: UInt64) throws {
    try sanitizeWebp(input: input)
}

public class SanitizedMetadata: ClonableHandleOwner {
    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MochiFfiErrorRef? {
        return mochi_sanitized_metadata_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> MochiFfiErrorRef? {
        return mochi_sanitized_metadata_destroy(handle)
    }

    /// The sanitized metadata, or nil if it didn't need to be sanitized.
    public var metadata: Data? {
        let metadata = withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningDataNoCopy {
                    mochi_sanitized_metadata_get_metadata($0, nativeHandle)
                }
            }
        }
        guard !metadata.isEmpty else { return nil }
        return metadata
    }

    /// The offset of the media data in the processed input.
    public var dataOffset: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_sanitized_metadata_get_data_offset($0, nativeHandle)
                }
            }
        }
    }

    /// The length of the media data in the processed input.
    public var dataLen: UInt64 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    mochi_sanitized_metadata_get_data_len($0, nativeHandle)
                }
            }
        }
    }
}

#endif
