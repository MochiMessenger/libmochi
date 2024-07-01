//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libmochi_net::chat::ChatServiceError;
use libmochi_net::infra::ws::WebSocketConnectError;
use libmochi_net::svr3::Error as Svr3Error;
use libmochi_protocol::*;
use mochi_crypto::Error as MochiCryptoError;
use mochi_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::support::describe_panic;

use super::{FutureCancelled, NullPointerError, UnexpectedPanic};

#[derive(Debug)]
#[repr(C)]
pub enum MochiErrorCode {
    #[allow(dead_code)]
    UnknownError = 1,
    InvalidState = 2,
    InternalError = 3,
    NullParameter = 4,
    InvalidArgument = 5,
    InvalidType = 6,
    InvalidUtf8String = 7,
    Cancelled = 8,

    ProtobufError = 10,

    LegacyCiphertextVersion = 21,
    UnknownCiphertextVersion = 22,
    UnrecognizedMessageVersion = 23,

    InvalidMessage = 30,
    SealedSenderSelfSend = 31,

    InvalidKey = 40,
    InvalidSignature = 41,
    InvalidAttestationData = 42,

    FingerprintVersionMismatch = 51,
    FingerprintParsingError = 52,

    UntrustedIdentity = 60,

    InvalidKeyIdentifier = 70,

    SessionNotFound = 80,
    InvalidRegistrationId = 81,
    InvalidSession = 82,
    InvalidSenderKeySession = 83,

    DuplicatedMessage = 90,

    CallbackError = 100,

    VerificationFailure = 110,

    UsernameCannotBeEmpty = 120,
    UsernameCannotStartWithDigit = 121,
    UsernameMissingSeparator = 122,
    UsernameBadDiscriminatorCharacter = 123,
    UsernameBadNicknameCharacter = 124,
    UsernameTooShort = 125,
    UsernameTooLong = 126,
    UsernameLinkInvalidEntropyDataLength = 127,
    UsernameLinkInvalid = 128,

    UsernameDiscriminatorCannotBeEmpty = 140,
    UsernameDiscriminatorCannotBeZero = 141,
    UsernameDiscriminatorCannotBeSingleDigit = 142,
    UsernameDiscriminatorCannotHaveLeadingZeros = 143,
    UsernameDiscriminatorTooLarge = 144,

    IoError = 130,
    #[allow(dead_code)]
    InvalidMediaInput = 131,
    #[allow(dead_code)]
    UnsupportedMediaInput = 132,

    ConnectionTimedOut = 133,
    NetworkProtocol = 134,
    RateLimited = 135,
    WebSocket = 136,
    CdsiInvalidToken = 137,
    ConnectionFailed = 138,
    ChatServiceInactive = 139,

    SvrDataMissing = 150,
    SvrRestoreFailed = 151,

    AppExpired = 160,
    DeviceDeregistered = 161,
}

pub trait UpcastAsAny {
    fn upcast_as_any(&self) -> &dyn std::any::Any;
}
impl<T: std::any::Any> UpcastAsAny for T {
    fn upcast_as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Error returned when asking for an attribute of an error that doesn't support that attribute.
pub struct WrongErrorKind;

pub trait FfiError: UpcastAsAny + fmt::Debug + Send + 'static {
    fn describe(&self) -> String;
    fn code(&self) -> MochiErrorCode;

    fn provide_address(&self) -> Result<ProtocolAddress, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_uuid(&self) -> Result<uuid::Uuid, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        Err(WrongErrorKind)
    }
    fn provide_tries_remaining(&self) -> Result<u32, WrongErrorKind> {
        Err(WrongErrorKind)
    }
}

/// The top-level error type (opaquely) returned to C clients when something goes wrong.
///
/// Ideally this would use [ThinBox][], and then we wouldn't need an extra level of indirection when
/// returning it to C, but unfortunately that isn't stable yet.
///
/// [ThinBox]: https://doc.rust-lang.org/std/boxed/struct.ThinBox.html
#[derive(Debug)]
pub struct MochiFfiError(Box<dyn FfiError + Send>);

impl MochiFfiError {
    pub fn downcast_ref<T: FfiError>(&self) -> Option<&T> {
        (*self.0).upcast_as_any().downcast_ref()
    }
}

/// MochiFfiError is a typed wrapper around a Box, and as such it's reasonable for it to have the
/// same Deref behavior as a Box. All the interesting functionality is present on the [`FfiError`]
/// trait.
impl std::ops::Deref for MochiFfiError {
    type Target = dyn FfiError;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl fmt::Display for MochiFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.describe())
    }
}

impl<T: FfiError> From<T> for MochiFfiError {
    fn from(mut value: T) -> Self {
        // Special case: if the error being boxed is an IoError containing a MochiProtocolError,
        // extract the MochiProtocolError up front.
        match (&mut value as &mut dyn std::any::Any).downcast_mut::<IoError>() {
            Some(e) => {
                let original_error = (e.kind() == IoErrorKind::Other)
                    .then(|| {
                        e.get_mut()
                            .and_then(|e| e.downcast_mut::<MochiProtocolError>())
                    })
                    .flatten()
                    .map(|e| {
                        // We can't get the inner error out without putting something in
                        // its place, so leave some random (cheap-to-construct) error.
                        // TODO: use IoError::downcast() once it is stabilized
                        // (https://github.com/rust-lang/rust/issues/99262).
                        std::mem::replace(e, MochiProtocolError::InvalidPreKeyId)
                    });
                if let Some(original_error) = original_error {
                    Self(Box::new(original_error))
                } else {
                    Self(Box::new(value))
                }
            }
            None => Self(Box::new(value)),
        }
    }
}

impl FfiError for MochiProtocolError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::InvalidArgument(_) => MochiErrorCode::InvalidArgument,
            Self::InvalidState(_, _) => MochiErrorCode::InvalidState,
            Self::InvalidProtobufEncoding => MochiErrorCode::ProtobufError,
            Self::CiphertextMessageTooShort(_)
            | Self::InvalidMessage(_, _)
            | Self::InvalidSealedSenderMessage(_)
            | Self::BadKEMCiphertextLength(_, _) => MochiErrorCode::InvalidMessage,
            Self::LegacyCiphertextVersion(_) => MochiErrorCode::LegacyCiphertextVersion,
            Self::UnrecognizedCiphertextVersion(_) => MochiErrorCode::UnknownCiphertextVersion,
            Self::UnrecognizedMessageVersion(_) | Self::UnknownSealedSenderVersion(_) => {
                MochiErrorCode::UnrecognizedMessageVersion
            }
            Self::FingerprintVersionMismatch(_, _) => MochiErrorCode::FingerprintVersionMismatch,
            Self::FingerprintParsingError => MochiErrorCode::FingerprintParsingError,
            Self::NoKeyTypeIdentifier
            | Self::BadKeyType(_)
            | Self::BadKeyLength(_, _)
            | Self::InvalidMacKeyLength(_)
            | Self::BadKEMKeyType(_)
            | Self::WrongKEMKeyType(_, _)
            | Self::BadKEMKeyLength(_, _) => MochiErrorCode::InvalidKey,
            Self::SignatureValidationFailed => MochiErrorCode::InvalidSignature,
            Self::UntrustedIdentity(_) => MochiErrorCode::UntrustedIdentity,
            Self::InvalidPreKeyId | Self::InvalidSignedPreKeyId | Self::InvalidKyberPreKeyId => {
                MochiErrorCode::InvalidKeyIdentifier
            }
            Self::NoSenderKeyState { .. } | Self::SessionNotFound(_) => {
                MochiErrorCode::SessionNotFound
            }
            Self::InvalidSessionStructure(_) => MochiErrorCode::InvalidSession,
            Self::InvalidSenderKeySession { .. } => MochiErrorCode::InvalidSenderKeySession,
            Self::InvalidRegistrationId(_, _) => MochiErrorCode::InvalidRegistrationId,
            Self::DuplicatedMessage(_, _) => MochiErrorCode::DuplicatedMessage,
            Self::FfiBindingError(_) => MochiErrorCode::InternalError,
            Self::ApplicationCallbackError(_, _) => MochiErrorCode::CallbackError,
            Self::SealedSenderSelfSend => MochiErrorCode::SealedSenderSelfSend,
        }
    }

    fn provide_address(&self) -> Result<ProtocolAddress, WrongErrorKind> {
        match self {
            Self::InvalidRegistrationId(address, _id) => Ok(address.clone()),
            _ => Err(WrongErrorKind),
        }
    }

    fn provide_uuid(&self) -> Result<uuid::Uuid, WrongErrorKind> {
        match self {
            Self::InvalidSenderKeySession { distribution_id } => Ok(*distribution_id),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for DeviceTransferError {
    fn describe(&self) -> String {
        format!("Device transfer operation failed: {self}")
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::KeyDecodingFailed => MochiErrorCode::InvalidKey,
            Self::InternalError(_) => MochiErrorCode::InternalError,
        }
    }
}

impl FfiError for HsmEnclaveError {
    fn describe(&self) -> String {
        format!("HSM enclave operation failed: {self}")
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::HSMCommunicationError(_) | Self::HSMHandshakeError(_) => {
                MochiErrorCode::InvalidMessage
            }
            Self::TrustedCodeError => MochiErrorCode::UntrustedIdentity,
            Self::InvalidPublicKeyError => MochiErrorCode::InvalidKey,
            Self::InvalidCodeHashError => MochiErrorCode::InvalidArgument,
            Self::InvalidBridgeStateError => MochiErrorCode::InvalidState,
        }
    }
}

impl FfiError for EnclaveError {
    fn describe(&self) -> String {
        format!("SGX operation failed: {self}")
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::AttestationError(_) | Self::NoiseError(_) | Self::NoiseHandshakeError(_) => {
                MochiErrorCode::InvalidMessage
            }
            Self::AttestationDataError { .. } => MochiErrorCode::InvalidAttestationData,
            Self::InvalidBridgeStateError => MochiErrorCode::InvalidState,
        }
    }
}

impl FfiError for PinError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::Argon2Error(_) | Self::DecodingError(_) | Self::MrenclaveLookupError => {
                MochiErrorCode::InvalidArgument
            }
        }
    }
}

impl FfiError for MochiCryptoError {
    fn describe(&self) -> String {
        format!("Cryptographic operation failed: {self}")
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::UnknownAlgorithm(_, _)
            | Self::InvalidKeySize
            | Self::InvalidNonceSize
            | Self::InvalidInputSize => MochiErrorCode::InvalidArgument,
            Self::InvalidTag => MochiErrorCode::InvalidMessage,
        }
    }
}

impl FfiError for ZkGroupVerificationFailure {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::VerificationFailure
    }
}

impl FfiError for ZkGroupDeserializationFailure {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::InvalidType
    }
}

impl FfiError for UsernameError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::MissingSeparator => MochiErrorCode::UsernameMissingSeparator,
            Self::NicknameCannotBeEmpty => MochiErrorCode::UsernameCannotBeEmpty,
            Self::NicknameCannotStartWithDigit => MochiErrorCode::UsernameCannotStartWithDigit,
            Self::BadNicknameCharacter => MochiErrorCode::UsernameBadNicknameCharacter,
            Self::NicknameTooShort => MochiErrorCode::UsernameTooShort,
            Self::NicknameTooLong => MochiErrorCode::UsernameTooLong,
            Self::DiscriminatorCannotBeEmpty => MochiErrorCode::UsernameDiscriminatorCannotBeEmpty,
            Self::DiscriminatorCannotBeZero => MochiErrorCode::UsernameDiscriminatorCannotBeZero,
            Self::DiscriminatorCannotBeSingleDigit => {
                MochiErrorCode::UsernameDiscriminatorCannotBeSingleDigit
            }
            Self::DiscriminatorCannotHaveLeadingZeros => {
                MochiErrorCode::UsernameDiscriminatorCannotHaveLeadingZeros
            }
            Self::BadDiscriminatorCharacter => MochiErrorCode::UsernameBadDiscriminatorCharacter,
            Self::DiscriminatorTooLarge => MochiErrorCode::UsernameDiscriminatorTooLarge,
        }
    }
}

impl FfiError for usernames::ProofVerificationFailure {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::VerificationFailure
    }
}

impl FfiError for UsernameLinkError {
    fn describe(&self) -> String {
        self.to_string()
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::InputDataTooLong => MochiErrorCode::UsernameTooLong,
            Self::InvalidEntropyDataLength => MochiErrorCode::UsernameLinkInvalidEntropyDataLength,
            Self::UsernameLinkDataTooShort
            | Self::HmacMismatch
            | Self::BadCiphertext
            | Self::InvalidDecryptedDataStructure => MochiErrorCode::UsernameLinkInvalid,
        }
    }
}

impl FfiError for IoError {
    fn describe(&self) -> String {
        format!("IO error: {self}")
    }

    fn code(&self) -> MochiErrorCode {
        // Parallels the unwrapping that happens when converting to a boxed MochiFfiError.
        (self.kind() == IoErrorKind::Other)
            .then(|| {
                Some(
                    self.get_ref()?
                        .downcast_ref::<MochiProtocolError>()?
                        .code(),
                )
            })
            .flatten()
            .unwrap_or(MochiErrorCode::IoError)
    }
}

impl FfiError for libmochi_net::cdsi::LookupError {
    fn describe(&self) -> String {
        match self {
            Self::Protocol | Self::InvalidResponse | Self::ParseError | Self::Server { .. } => {
                format!("Protocol error: {self}")
            }
            Self::AttestationError(e) => e.describe(),
            Self::RateLimited {
                retry_after_seconds,
            } => format!("Rate limited; try again after {retry_after_seconds}s"),
            Self::InvalidToken => "CDSI request token was invalid".to_owned(),
            Self::ConnectTransport(e) => format!("IO error: {e}"),
            Self::WebSocket(e) => format!("WebSocket error: {e}"),
            Self::ConnectionTimedOut => "Connect timed out".to_owned(),
            Self::InvalidArgument { .. } => format!("invalid argument: {self}"),
        }
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::Protocol | Self::InvalidResponse | Self::ParseError | Self::Server { .. } => {
                MochiErrorCode::NetworkProtocol
            }
            Self::AttestationError(e) => e.code(),
            Self::RateLimited { .. } => MochiErrorCode::RateLimited,
            Self::InvalidToken => MochiErrorCode::CdsiInvalidToken,
            Self::ConnectTransport(_) => MochiErrorCode::IoError,
            Self::WebSocket(_) => MochiErrorCode::WebSocket,
            Self::ConnectionTimedOut => MochiErrorCode::ConnectionTimedOut,
            Self::InvalidArgument { .. } => MochiErrorCode::InvalidArgument,
        }
    }

    fn provide_retry_after_seconds(&self) -> Result<u32, WrongErrorKind> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => Ok(*retry_after_seconds),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for Svr3Error {
    fn describe(&self) -> String {
        match self {
            Self::Connect(WebSocketConnectError::Timeout) | Self::ConnectionTimedOut => {
                "Connect timed out".to_owned()
            }
            Self::Connect(WebSocketConnectError::Transport(e)) => format!("IO error: {e}"),
            Self::Connect(
                e @ (WebSocketConnectError::WebSocketError(_)
                | WebSocketConnectError::RejectedByServer(_)),
            ) => {
                format!("WebSocket error: {e}")
            }
            Self::Service(e) => format!("WebSocket error: {e}"),
            Self::Protocol(e) => format!("Protocol error: {e}"),
            Self::AttestationError(inner) => inner.describe(),
            Self::RequestFailed(_) | Self::RestoreFailed(_) | Self::DataMissing => {
                format!("SVR error: {self}")
            }
        }
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::Connect(e) => match e {
                WebSocketConnectError::Transport(_) => MochiErrorCode::IoError,
                WebSocketConnectError::Timeout => MochiErrorCode::ConnectionTimedOut,
                WebSocketConnectError::WebSocketError(_)
                | WebSocketConnectError::RejectedByServer(_) => MochiErrorCode::WebSocket,
            },
            Self::Service(_) => MochiErrorCode::WebSocket,
            Self::ConnectionTimedOut => MochiErrorCode::ConnectionTimedOut,
            Self::AttestationError(inner) => inner.code(),
            Self::Protocol(_) => MochiErrorCode::NetworkProtocol,
            Self::RequestFailed(_) => MochiErrorCode::UnknownError,
            Self::RestoreFailed(_) => MochiErrorCode::SvrRestoreFailed,
            Self::DataMissing => MochiErrorCode::SvrDataMissing,
        }
    }

    fn provide_tries_remaining(&self) -> Result<u32, WrongErrorKind> {
        match self {
            Self::RestoreFailed(tries_remaining) => Ok(*tries_remaining),
            _ => Err(WrongErrorKind),
        }
    }
}

impl FfiError for ChatServiceError {
    fn describe(&self) -> String {
        match self {
            Self::WebSocket(e) => format!("WebSocket error: {e}"),
            Self::AllConnectionRoutesFailed { .. } | Self::ServiceUnavailable => {
                "Connection failed".to_owned()
            }
            Self::UnexpectedFrameReceived
            | Self::ServerRequestMissingId
            | Self::IncomingDataInvalid => format!("Protocol error: {self}"),
            Self::FailedToPassMessageToIncomingChannel | Self::RequestHasInvalidHeader => {
                format!("internal error: {self}")
            }
            Self::Timeout | Self::TimeoutEstablishingConnection { .. } => {
                "Connect timed out".to_owned()
            }
            Self::ServiceInactive => "Chat service inactive".to_owned(),
            Self::AppExpired => "App expired".to_owned(),
            Self::DeviceDeregistered => "Device deregistered or delinked".to_owned(),
        }
    }

    fn code(&self) -> MochiErrorCode {
        match self {
            Self::WebSocket(_) => MochiErrorCode::WebSocket,
            Self::AllConnectionRoutesFailed { .. } | Self::ServiceUnavailable => {
                MochiErrorCode::ConnectionFailed
            }
            Self::UnexpectedFrameReceived
            | Self::ServerRequestMissingId
            | Self::IncomingDataInvalid => MochiErrorCode::NetworkProtocol,
            Self::FailedToPassMessageToIncomingChannel | Self::RequestHasInvalidHeader => {
                MochiErrorCode::InternalError
            }
            Self::Timeout | Self::TimeoutEstablishingConnection { .. } => {
                MochiErrorCode::ConnectionTimedOut
            }
            Self::ServiceInactive => MochiErrorCode::ChatServiceInactive,
            Self::AppExpired => MochiErrorCode::AppExpired,
            Self::DeviceDeregistered => MochiErrorCode::DeviceDeregistered,
        }
    }
}

impl FfiError for http::uri::InvalidUri {
    fn describe(&self) -> String {
        format!("invalid argument: {self}")
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::InvalidArgument
    }
}

#[cfg(feature = "mochi-media")]
impl FfiError for mochi_media::sanitize::mp4::Error {
    fn describe(&self) -> String {
        match self {
            Self::Io(e) => e.describe(),
            Self::Parse(e) => format!("Mp4 sanitizer failed to parse mp4 file: {e}"),
        }
    }

    fn code(&self) -> MochiErrorCode {
        use mochi_media::sanitize::mp4::ParseError;
        match self {
            Self::Io(e) => e.code(),
            Self::Parse(e) => match e.kind {
                ParseError::InvalidBoxLayout { .. }
                | ParseError::InvalidInput { .. }
                | ParseError::MissingRequiredBox { .. }
                | ParseError::TruncatedBox => MochiErrorCode::InvalidMediaInput,

                ParseError::UnsupportedBoxLayout { .. }
                | ParseError::UnsupportedBox { .. }
                | ParseError::UnsupportedFormat { .. } => MochiErrorCode::UnsupportedMediaInput,
            },
        }
    }
}

#[cfg(feature = "mochi-media")]
impl FfiError for mochi_media::sanitize::webp::Error {
    fn describe(&self) -> String {
        match self {
            Self::Io(e) => e.describe(),
            Self::Parse(e) => format!("WebP sanitizer failed to parse webp file: {e}"),
        }
    }

    fn code(&self) -> MochiErrorCode {
        use mochi_media::sanitize::webp::ParseError;
        match self {
            Self::Io(e) => e.code(),
            Self::Parse(e) => match e.kind {
                ParseError::InvalidChunkLayout { .. }
                | ParseError::InvalidInput { .. }
                | ParseError::InvalidVp8lPrefixCode { .. }
                | ParseError::MissingRequiredChunk { .. }
                | ParseError::TruncatedChunk => MochiErrorCode::InvalidMediaInput,

                ParseError::UnsupportedChunk { .. } | ParseError::UnsupportedVp8lVersion { .. } => {
                    MochiErrorCode::UnsupportedMediaInput
                }
            },
        }
    }
}

impl FfiError for NullPointerError {
    fn describe(&self) -> String {
        "null pointer".to_owned()
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::NullParameter
    }
}

impl FfiError for UnexpectedPanic {
    fn describe(&self) -> String {
        format!("unexpected panic: {}", describe_panic(&self.0))
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::InternalError
    }
}

impl FfiError for std::str::Utf8Error {
    fn describe(&self) -> String {
        "invalid UTF8 string".to_owned()
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::InvalidUtf8String
    }
}

impl FfiError for FutureCancelled {
    fn describe(&self) -> String {
        "cancelled".to_owned()
    }

    fn code(&self) -> MochiErrorCode {
        MochiErrorCode::Cancelled
    }
}

pub type MochiFfiResult<T> = Result<T, MochiFfiError>;

/// Represents an error returned by a callback, following the C conventions that 0 means "success".
#[derive(Debug)]
pub struct CallbackError {
    value: std::num::NonZeroI32,
}

impl CallbackError {
    /// Returns `Ok(())` if `value` is zero; otherwise, wraps the value in `Self` as an error.
    pub fn check(value: i32) -> Result<(), Self> {
        match std::num::NonZeroI32::try_from(value).ok() {
            None => Ok(()),
            Some(value) => Err(Self { value }),
        }
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error code {}", self.value)
    }
}

impl std::error::Error for CallbackError {}
