//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import MochiFfi

public enum MochiError: Error {
    case invalidState(String)
    case internalError(String)
    case nullParameter(String)
    case invalidArgument(String)
    case invalidType(String)
    case invalidUtf8String(String)
    case protobufError(String)
    case legacyCiphertextVersion(String)
    case unknownCiphertextVersion(String)
    case unrecognizedMessageVersion(String)
    case invalidMessage(String)
    case invalidKey(String)
    case invalidSignature(String)
    case invalidAttestationData(String)
    case fingerprintVersionMismatch(String)
    case fingerprintParsingError(String)
    case sealedSenderSelfSend(String)
    case untrustedIdentity(String)
    case invalidKeyIdentifier(String)
    case sessionNotFound(String)
    case invalidSession(String)
    case invalidRegistrationId(address: ProtocolAddress, message: String)
    case invalidSenderKeySession(distributionId: UUID, message: String)
    case duplicatedMessage(String)
    case verificationFailed(String)
    case nicknameCannotBeEmpty(String)
    case nicknameCannotStartWithDigit(String)
    case missingSeparator(String)
    case badDiscriminatorCharacter(String)
    case badNicknameCharacter(String)
    case nicknameTooShort(String)
    case nicknameTooLong(String)
    case usernameLinkInvalidEntropyDataLength(String)
    case usernameLinkInvalid(String)
    case usernameDiscriminatorCannotBeEmpty(String)
    case usernameDiscriminatorCannotBeZero(String)
    case usernameDiscriminatorCannotBeSingleDigit(String)
    case usernameDiscriminatorCannotHaveLeadingZeros(String)
    case usernameDiscriminatorTooLarge(String)
    case ioError(String)
    case invalidMediaInput(String)
    case unsupportedMediaInput(String)
    case callbackError(String)
    case webSocketError(String)
    case connectionTimeoutError(String)
    case connectionFailed(String)
    case networkProtocolError(String)
    case cdsiInvalidToken(String)
    case rateLimitedError(retryAfter: TimeInterval, message: String)
    case svrDataMissing(String)
    case svrRestoreFailed(triesRemaining: UInt32, message: String)
    case chatServiceInactive(String)
    case appExpired(String)
    case deviceDeregistered(String)

    case unknown(UInt32, String)
}

internal typealias MochiFfiErrorRef = OpaquePointer

internal func checkError(_ error: MochiFfiErrorRef?) throws {
    guard let error = error else { return }

    let errType = mochi_error_get_type(error)
    // If this actually throws we'd have an infinite loop before we hit the 'try!'.
    let errStr = try! invokeFnReturningString {
        mochi_error_get_message(error, $0)
    }
    defer { mochi_error_free(error) }

    switch MochiErrorCode(errType) {
    case MochiErrorCodeCancelled:
        // Special case: don't use MochiError for this one.
        throw CancellationError()
    case MochiErrorCodeInvalidState:
        throw MochiError.invalidState(errStr)
    case MochiErrorCodeInternalError:
        throw MochiError.internalError(errStr)
    case MochiErrorCodeNullParameter:
        throw MochiError.nullParameter(errStr)
    case MochiErrorCodeInvalidArgument:
        throw MochiError.invalidArgument(errStr)
    case MochiErrorCodeInvalidType:
        throw MochiError.invalidType(errStr)
    case MochiErrorCodeInvalidUtf8String:
        throw MochiError.invalidUtf8String(errStr)
    case MochiErrorCodeProtobufError:
        throw MochiError.protobufError(errStr)
    case MochiErrorCodeLegacyCiphertextVersion:
        throw MochiError.legacyCiphertextVersion(errStr)
    case MochiErrorCodeUnknownCiphertextVersion:
        throw MochiError.unknownCiphertextVersion(errStr)
    case MochiErrorCodeUnrecognizedMessageVersion:
        throw MochiError.unrecognizedMessageVersion(errStr)
    case MochiErrorCodeInvalidMessage:
        throw MochiError.invalidMessage(errStr)
    case MochiErrorCodeFingerprintParsingError:
        throw MochiError.fingerprintParsingError(errStr)
    case MochiErrorCodeSealedSenderSelfSend:
        throw MochiError.sealedSenderSelfSend(errStr)
    case MochiErrorCodeInvalidKey:
        throw MochiError.invalidKey(errStr)
    case MochiErrorCodeInvalidSignature:
        throw MochiError.invalidSignature(errStr)
    case MochiErrorCodeInvalidAttestationData:
        throw MochiError.invalidAttestationData(errStr)
    case MochiErrorCodeFingerprintVersionMismatch:
        throw MochiError.fingerprintVersionMismatch(errStr)
    case MochiErrorCodeUntrustedIdentity:
        throw MochiError.untrustedIdentity(errStr)
    case MochiErrorCodeInvalidKeyIdentifier:
        throw MochiError.invalidKeyIdentifier(errStr)
    case MochiErrorCodeSessionNotFound:
        throw MochiError.sessionNotFound(errStr)
    case MochiErrorCodeInvalidSession:
        throw MochiError.invalidSession(errStr)
    case MochiErrorCodeInvalidRegistrationId:
        let address: ProtocolAddress = try invokeFnReturningNativeHandle {
            mochi_error_get_address(error, $0)
        }
        throw MochiError.invalidRegistrationId(address: address, message: errStr)
    case MochiErrorCodeInvalidSenderKeySession:
        let distributionId = try invokeFnReturningUuid {
            mochi_error_get_uuid(error, $0)
        }
        throw MochiError.invalidSenderKeySession(distributionId: distributionId, message: errStr)
    case MochiErrorCodeDuplicatedMessage:
        throw MochiError.duplicatedMessage(errStr)
    case MochiErrorCodeVerificationFailure:
        throw MochiError.verificationFailed(errStr)
    case MochiErrorCodeUsernameCannotBeEmpty:
        throw MochiError.nicknameCannotBeEmpty(errStr)
    case MochiErrorCodeUsernameCannotStartWithDigit:
        throw MochiError.nicknameCannotStartWithDigit(errStr)
    case MochiErrorCodeUsernameMissingSeparator:
        throw MochiError.missingSeparator(errStr)
    case MochiErrorCodeUsernameBadDiscriminatorCharacter:
        throw MochiError.badDiscriminatorCharacter(errStr)
    case MochiErrorCodeUsernameBadNicknameCharacter:
        throw MochiError.badNicknameCharacter(errStr)
    case MochiErrorCodeUsernameTooShort:
        throw MochiError.nicknameTooShort(errStr)
    case MochiErrorCodeUsernameTooLong:
        throw MochiError.nicknameTooLong(errStr)
    case MochiErrorCodeUsernameDiscriminatorCannotBeEmpty:
        throw MochiError.usernameDiscriminatorCannotBeEmpty(errStr)
    case MochiErrorCodeUsernameDiscriminatorCannotBeZero:
        throw MochiError.usernameDiscriminatorCannotBeZero(errStr)
    case MochiErrorCodeUsernameDiscriminatorCannotBeSingleDigit:
        throw MochiError.usernameDiscriminatorCannotBeSingleDigit(errStr)
    case MochiErrorCodeUsernameDiscriminatorCannotHaveLeadingZeros:
        throw MochiError.usernameDiscriminatorCannotHaveLeadingZeros(errStr)
    case MochiErrorCodeUsernameDiscriminatorTooLarge:
        throw MochiError.usernameDiscriminatorTooLarge(errStr)
    case MochiErrorCodeUsernameLinkInvalidEntropyDataLength:
        throw MochiError.usernameLinkInvalidEntropyDataLength(errStr)
    case MochiErrorCodeUsernameLinkInvalid:
        throw MochiError.usernameLinkInvalid(errStr)
    case MochiErrorCodeIoError:
        throw MochiError.ioError(errStr)
    case MochiErrorCodeInvalidMediaInput:
        throw MochiError.invalidMediaInput(errStr)
    case MochiErrorCodeUnsupportedMediaInput:
        throw MochiError.unsupportedMediaInput(errStr)
    case MochiErrorCodeCallbackError:
        throw MochiError.callbackError(errStr)
    case MochiErrorCodeWebSocket:
        throw MochiError.webSocketError(errStr)
    case MochiErrorCodeConnectionTimedOut:
        throw MochiError.connectionTimeoutError(errStr)
    case MochiErrorCodeConnectionFailed:
        throw MochiError.connectionFailed(errStr)
    case MochiErrorCodeNetworkProtocol:
        throw MochiError.networkProtocolError(errStr)
    case MochiErrorCodeCdsiInvalidToken:
        throw MochiError.cdsiInvalidToken(errStr)
    case MochiErrorCodeRateLimited:
        let retryAfterSeconds = try invokeFnReturningInteger {
            mochi_error_get_retry_after_seconds(error, $0)
        }
        throw MochiError.rateLimitedError(retryAfter: TimeInterval(retryAfterSeconds), message: errStr)
    case MochiErrorCodeSvrDataMissing:
        throw MochiError.svrDataMissing(errStr)
    case MochiErrorCodeSvrRestoreFailed:
        let triesRemaining = try invokeFnReturningInteger {
            mochi_error_get_tries_remaining(error, $0)
        }
        throw MochiError.svrRestoreFailed(triesRemaining: triesRemaining, message: errStr)
    case MochiErrorCodeChatServiceInactive:
        throw MochiError.chatServiceInactive(errStr)
    case MochiErrorCodeAppExpired:
        throw MochiError.appExpired(errStr)
    case MochiErrorCodeDeviceDeregistered:
        throw MochiError.deviceDeregistered(errStr)
    default:
        throw MochiError.unknown(errType, errStr)
    }
}

internal func failOnError(_ error: MochiFfiErrorRef?) {
    failOnError { try checkError(error) }
}

internal func failOnError<Result>(_ fn: () throws -> Result, file: StaticString = #file, line: UInt32 = #line) -> Result {
    do {
        return try fn()
    } catch {
        guard let loggerBridge = LoggerBridge.shared else {
            fatalError("unexpected error: \(error)", file: file, line: UInt(line))
        }
        "unexpected error: \(error)".withCString {
            loggerBridge.logger.logFatal(file: String(describing: file), line: line, message: $0)
        }
    }
}
