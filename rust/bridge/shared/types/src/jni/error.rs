//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use http::uri::InvalidUri;
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::time::Duration;

use jni::objects::{GlobalRef, JObject, JString, JThrowable};
use jni::{JNIEnv, JavaVM};

use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use libmochi_net::chat::ChatServiceError;
use libmochi_net::infra::ws::{WebSocketConnectError, WebSocketServiceError};
use libmochi_protocol::*;
use mochi_crypto::Error as MochiCryptoError;
use mochi_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::net::cdsi::CdsiError;
use crate::support::describe_panic;

use super::*;

/// The top-level error type for when something goes wrong.
#[derive(Debug, thiserror::Error)]
pub enum MochiJniError {
    Protocol(MochiProtocolError),
    DeviceTransfer(DeviceTransferError),
    MochiCrypto(MochiCryptoError),
    HsmEnclave(HsmEnclaveError),
    Enclave(EnclaveError),
    Pin(PinError),
    ZkGroupDeserializationFailure(ZkGroupDeserializationFailure),
    ZkGroupVerificationFailure(ZkGroupVerificationFailure),
    UsernameError(UsernameError),
    UsernameProofError(usernames::ProofVerificationFailure),
    UsernameLinkError(UsernameLinkError),
    Io(IoError),
    #[cfg(feature = "mochi-media")]
    Mp4SanitizeParse(mochi_media::sanitize::mp4::ParseErrorReport),
    #[cfg(feature = "mochi-media")]
    WebpSanitizeParse(mochi_media::sanitize::webp::ParseErrorReport),
    Cdsi(CdsiError),
    Svr3(libmochi_net::svr3::Error),
    WebSocket(#[from] WebSocketServiceError),
    ChatService(ChatServiceError),
    InvalidUri(InvalidUri),
    ConnectTimedOut,
    Bridge(BridgeLayerError),
    TestingError {
        exception_class: ClassName<'static>,
    },
}

/// Subset of errors that can happen in the bridge layer.
///
/// These errors will always be converted to RuntimeExceptions or Errors, i.e. unchecked throwables,
/// except for the [`Self::CallbackException`] case, which is rethrown.
#[derive(Debug)]
pub enum BridgeLayerError {
    Jni(jni::errors::Error),
    BadArgument(String),
    BadJniParameter(&'static str),
    UnexpectedJniResultType(&'static str, &'static str),
    NullPointer(Option<&'static str>),
    IntegerOverflow(String),
    IncorrectArrayLength { expected: usize, actual: usize },
    CallbackException(&'static str, ThrownException),
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}

impl fmt::Display for MochiJniError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MochiJniError::Protocol(s) => write!(f, "{}", s),
            MochiJniError::DeviceTransfer(s) => write!(f, "{}", s),
            MochiJniError::HsmEnclave(e) => write!(f, "{}", e),
            MochiJniError::Enclave(e) => write!(f, "{}", e),
            MochiJniError::Pin(e) => write!(f, "{}", e),
            MochiJniError::MochiCrypto(s) => write!(f, "{}", s),
            MochiJniError::ZkGroupVerificationFailure(e) => write!(f, "{}", e),
            MochiJniError::ZkGroupDeserializationFailure(e) => write!(f, "{}", e),
            MochiJniError::UsernameError(e) => write!(f, "{}", e),
            MochiJniError::UsernameProofError(e) => write!(f, "{}", e),
            MochiJniError::UsernameLinkError(e) => write!(f, "{}", e),
            MochiJniError::Io(e) => write!(f, "{}", e),
            #[cfg(feature = "mochi-media")]
            MochiJniError::Mp4SanitizeParse(e) => write!(f, "{}", e),
            #[cfg(feature = "mochi-media")]
            MochiJniError::WebpSanitizeParse(e) => write!(f, "{}", e),
            MochiJniError::Cdsi(e) => write!(f, "{}", e),
            MochiJniError::ChatService(e) => write!(f, "{}", e),
            MochiJniError::InvalidUri(e) => write!(f, "{}", e),
            MochiJniError::WebSocket(e) => write!(f, "{e}"),
            MochiJniError::ConnectTimedOut => write!(f, "connect timed out"),
            MochiJniError::Svr3(e) => write!(f, "{}", e),
            MochiJniError::Bridge(e) => write!(f, "{}", e),
            MochiJniError::TestingError { exception_class } => {
                write!(f, "TestingError({})", exception_class)
            }
        }
    }
}

impl fmt::Display for BridgeLayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jni(s) => write!(f, "JNI error {}", s),
            Self::NullPointer(None) => write!(f, "unexpected null"),
            Self::NullPointer(Some(expected_type)) => {
                write!(f, "got null where {expected_type} instance is expected")
            }
            Self::BadArgument(m) => write!(f, "{}", m),
            Self::BadJniParameter(m) => write!(f, "bad parameter type {}", m),
            Self::UnexpectedJniResultType(m, t) => {
                write!(f, "calling {} returned unexpected type {}", m, t)
            }
            Self::IntegerOverflow(m) => {
                write!(f, "integer overflow during conversion of {}", m)
            }
            Self::IncorrectArrayLength { expected, actual } => {
                write!(
                    f,
                    "expected array with length {} (was {})",
                    expected, actual
                )
            }
            Self::CallbackException(callback_name, exception) => {
                write!(f, "exception in method call '{callback_name}': {exception}")
            }
            Self::UnexpectedPanic(e) => {
                write!(f, "unexpected panic: {}", describe_panic(e))
            }
        }
    }
}

impl From<MochiProtocolError> for MochiJniError {
    fn from(e: MochiProtocolError) -> MochiJniError {
        MochiJniError::Protocol(e)
    }
}

impl From<DeviceTransferError> for MochiJniError {
    fn from(e: DeviceTransferError) -> MochiJniError {
        MochiJniError::DeviceTransfer(e)
    }
}

impl From<HsmEnclaveError> for MochiJniError {
    fn from(e: HsmEnclaveError) -> MochiJniError {
        MochiJniError::HsmEnclave(e)
    }
}

impl From<EnclaveError> for MochiJniError {
    fn from(e: EnclaveError) -> MochiJniError {
        MochiJniError::Enclave(e)
    }
}

impl From<PinError> for MochiJniError {
    fn from(e: PinError) -> MochiJniError {
        MochiJniError::Pin(e)
    }
}

impl From<MochiCryptoError> for MochiJniError {
    fn from(e: MochiCryptoError) -> MochiJniError {
        MochiJniError::MochiCrypto(e)
    }
}

impl From<ZkGroupVerificationFailure> for MochiJniError {
    fn from(e: ZkGroupVerificationFailure) -> MochiJniError {
        MochiJniError::ZkGroupVerificationFailure(e)
    }
}

impl From<ZkGroupDeserializationFailure> for MochiJniError {
    fn from(e: ZkGroupDeserializationFailure) -> MochiJniError {
        MochiJniError::ZkGroupDeserializationFailure(e)
    }
}

impl From<UsernameError> for MochiJniError {
    fn from(e: UsernameError) -> Self {
        MochiJniError::UsernameError(e)
    }
}

impl From<usernames::ProofVerificationFailure> for MochiJniError {
    fn from(e: usernames::ProofVerificationFailure) -> Self {
        MochiJniError::UsernameProofError(e)
    }
}

impl From<UsernameLinkError> for MochiJniError {
    fn from(e: UsernameLinkError) -> Self {
        MochiJniError::UsernameLinkError(e)
    }
}

impl From<InvalidUri> for MochiJniError {
    fn from(e: InvalidUri) -> Self {
        MochiJniError::InvalidUri(e)
    }
}

impl From<ChatServiceError> for MochiJniError {
    fn from(e: ChatServiceError) -> Self {
        MochiJniError::ChatService(e)
    }
}

impl From<IoError> for MochiJniError {
    fn from(e: IoError) -> MochiJniError {
        Self::Io(e)
    }
}

#[cfg(feature = "mochi-media")]
impl From<mochi_media::sanitize::mp4::Error> for MochiJniError {
    fn from(e: mochi_media::sanitize::mp4::Error) -> Self {
        use mochi_media::sanitize::mp4::Error;
        match e {
            Error::Io(e) => Self::Io(e),
            Error::Parse(e) => Self::Mp4SanitizeParse(e),
        }
    }
}

#[cfg(feature = "mochi-media")]
impl From<mochi_media::sanitize::webp::Error> for MochiJniError {
    fn from(e: mochi_media::sanitize::webp::Error) -> Self {
        use mochi_media::sanitize::webp::Error;
        match e {
            Error::Io(e) => Self::Io(e),
            Error::Parse(e) => Self::WebpSanitizeParse(e),
        }
    }
}

impl From<libmochi_net::cdsi::LookupError> for MochiJniError {
    fn from(e: libmochi_net::cdsi::LookupError) -> MochiJniError {
        use libmochi_net::cdsi::LookupError;
        MochiJniError::Cdsi(match e {
            LookupError::ConnectionTimedOut => return MochiJniError::ConnectTimedOut,
            LookupError::AttestationError(e) => return e.into(),
            LookupError::ConnectTransport(e) => return IoError::from(e).into(),
            LookupError::WebSocket(e) => return e.into(),
            LookupError::InvalidArgument { server_reason: _ } => {
                return MochiJniError::Protocol(MochiProtocolError::InvalidArgument(
                    e.to_string(),
                ))
            }
            LookupError::InvalidResponse => CdsiError::InvalidResponse,
            LookupError::Protocol => CdsiError::Protocol,
            LookupError::RateLimited {
                retry_after_seconds,
            } => CdsiError::RateLimited {
                retry_after: Duration::from_secs(retry_after_seconds.into()),
            },
            LookupError::ParseError => CdsiError::ParseError,
            LookupError::InvalidToken => CdsiError::InvalidToken,
            LookupError::Server { reason } => CdsiError::Server { reason },
        })
    }
}

impl From<BridgeLayerError> for MochiJniError {
    fn from(e: BridgeLayerError) -> MochiJniError {
        MochiJniError::Bridge(e)
    }
}

impl From<jni::errors::Error> for BridgeLayerError {
    fn from(e: jni::errors::Error) -> BridgeLayerError {
        BridgeLayerError::Jni(e)
    }
}

impl From<Svr3Error> for MochiJniError {
    fn from(err: Svr3Error) -> Self {
        match err {
            Svr3Error::Connect(inner) => match inner {
                WebSocketConnectError::Timeout => MochiJniError::ConnectTimedOut,
                WebSocketConnectError::Transport(e) => MochiJniError::Io(e.into()),
                WebSocketConnectError::WebSocketError(e) => WebSocketServiceError::from(e).into(),
                WebSocketConnectError::RejectedByServer(response) => {
                    WebSocketServiceError::Http(response).into()
                }
            },
            Svr3Error::ConnectionTimedOut => MochiJniError::ConnectTimedOut,
            Svr3Error::Service(inner) => inner.into(),
            Svr3Error::AttestationError(inner) => inner.into(),
            Svr3Error::Protocol(_)
            | Svr3Error::RequestFailed(_)
            | Svr3Error::RestoreFailed(_)
            | Svr3Error::DataMissing => MochiJniError::Svr3(err),
        }
    }
}

impl From<jni::errors::Error> for MochiJniError {
    fn from(e: jni::errors::Error) -> MochiJniError {
        BridgeLayerError::from(e).into()
    }
}

impl From<MochiJniError> for MochiProtocolError {
    fn from(err: MochiJniError) -> MochiProtocolError {
        match err {
            MochiJniError::Protocol(e) => e,
            MochiJniError::Bridge(BridgeLayerError::BadJniParameter(m)) => {
                MochiProtocolError::InvalidArgument(m.to_string())
            }
            MochiJniError::Bridge(BridgeLayerError::CallbackException(callback, exception)) => {
                MochiProtocolError::ApplicationCallbackError(callback, Box::new(exception))
            }
            _ => MochiProtocolError::FfiBindingError(format!("{}", err)),
        }
    }
}

impl From<MochiJniError> for IoError {
    fn from(err: MochiJniError) -> Self {
        match err {
            MochiJniError::Io(e) => e,
            MochiJniError::Bridge(BridgeLayerError::CallbackException(
                _method_name,
                exception,
            )) => IoError::new(IoErrorKind::Other, exception),
            e => IoError::new(IoErrorKind::Other, e.to_string()),
        }
    }
}

pub type MochiJniResult<T> = Result<T, MochiJniError>;

/// A lifetime-less reference to a thrown Java exception that can be used as an [`Error`].
///
/// `ThrownException` allows a Java exception to be safely persisted past the lifetime of a
/// particular call.
///
/// Ideally, `ThrownException` should be Dropped on the thread the JVM is running on; see
/// [`jni::objects::GlobalRef`] for more details.
pub struct ThrownException {
    // GlobalRef already carries a JavaVM reference, but it's not accessible to us.
    jvm: JavaVM,
    exception_ref: GlobalRef,
}

impl ThrownException {
    /// Gets the wrapped exception as a live object with a lifetime.
    pub fn as_obj(&self) -> &JThrowable<'static> {
        self.exception_ref.as_obj().into()
    }

    /// Persists the given throwable.
    pub fn new<'a>(
        env: &JNIEnv<'a>,
        throwable: impl AsRef<JThrowable<'a>>,
    ) -> Result<Self, BridgeLayerError> {
        assert!(!throwable.as_ref().is_null());
        Ok(Self {
            jvm: env.get_java_vm()?,
            exception_ref: env.new_global_ref(throwable.as_ref())?,
        })
    }

    pub fn class_name(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let class_type = env.get_object_class(self.exception_ref.as_obj())?;
        let class_name: JObject = call_method_checked(
            env,
            class_type,
            "getCanonicalName",
            jni_args!(() -> java.lang.String),
        )?;

        Ok(env.get_string(&JString::from(class_name))?.into())
    }

    pub fn message(&self, env: &mut JNIEnv) -> Result<String, BridgeLayerError> {
        let message: JObject = call_method_checked(
            env,
            self.exception_ref.as_obj(),
            "getMessage",
            jni_args!(() -> java.lang.String),
        )?;
        Ok(env.get_string(&JString::from(message))?.into())
    }
}

impl fmt::Display for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = &mut self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

        let exn_type = self.class_name(env);
        let exn_type = exn_type.as_deref().unwrap_or("<unknown>");

        if let Ok(message) = self.message(env) {
            write!(f, "exception {} \"{}\"", exn_type, message)
        } else {
            write!(f, "exception {}", exn_type)
        }
    }
}

impl fmt::Debug for ThrownException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = &mut self.jvm.attach_current_thread().map_err(|_| fmt::Error)?;

        let exn_type = self.class_name(env);
        let exn_type = exn_type.as_deref().unwrap_or("<unknown>");

        let obj_addr = **self.exception_ref.as_obj();

        if let Ok(message) = self.message(env) {
            write!(f, "exception {} ({:p}) \"{}\"", exn_type, obj_addr, message)
        } else {
            write!(f, "exception {} ({:p})", exn_type, obj_addr)
        }
    }
}

impl std::error::Error for ThrownException {}
