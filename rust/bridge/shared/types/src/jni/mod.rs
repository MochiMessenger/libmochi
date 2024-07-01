//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use attest::enclave::Error as EnclaveError;
use attest::hsm_enclave::Error as HsmEnclaveError;
use device_transfer::Error as DeviceTransferError;
use jni::objects::{GlobalRef, JThrowable, JValue, JValueOwned};
use jni::JavaVM;
use libmochi_net::infra::ws::WebSocketServiceError;
use libmochi_net::svr3::Error as Svr3Error;
use libmochi_protocol::*;
use mochi_crypto::Error as MochiCryptoError;
use mochi_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};

use crate::net::cdsi::CdsiError;

pub use jni::objects::{
    AutoElements, JByteArray, JClass, JLongArray, JObject, JObjectArray, JString, ReleaseMode,
};
pub use jni::sys::{jboolean, jint, jlong};
pub use jni::JNIEnv;

#[macro_use]
mod args;
pub use args::*;

mod class_lookup;
pub use class_lookup::*;

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod futures;
pub use futures::*;

mod io;
pub use io::*;
use libmochi_net::chat::ChatServiceError;

mod storage;
pub use storage::*;

/// The type of boxed Rust values, as surfaced in JavaScript.
pub type ObjectHandle = jlong;

// Aliases with a certain spelling that gen_java_decl.py will pick out when generating Native.java.
pub type JavaArrayOfByteArray<'a> = JObjectArray<'a>;
pub type JavaByteBufferArray<'a> = JObjectArray<'a>;
pub type JavaObject<'a> = JObject<'a>;
pub type JavaUUID<'a> = JObject<'a>;
pub type JavaCiphertextMessage<'a> = JObject<'a>;
pub type JavaMap<'a> = JObject<'a>;

/// Return type marker for `bridge_fn`s that return Result, which gen_java_decl.py will pick out
/// when generating Native.java.
pub type Throwing<T> = T;

/// A Java wrapper for a `CompletableFuture` type.
#[derive(Default)]
#[repr(transparent)] // Ensures that the representation is the same as JObject.
pub struct JavaCompletableFuture<'a, T> {
    future_object: JObject<'a>,
    result: PhantomData<fn(T)>,
}

impl<'a, T> From<JObject<'a>> for JavaCompletableFuture<'a, T> {
    fn from(future_object: JObject<'a>) -> Self {
        Self {
            future_object,
            result: PhantomData,
        }
    }
}

impl<'a, T> From<JavaCompletableFuture<'a, T>> for JObject<'a> {
    fn from(value: JavaCompletableFuture<'a, T>) -> Self {
        value.future_object
    }
}

fn convert_to_exception<'a, 'env, F>(env: &'a mut JNIEnv<'env>, error: MochiJniError, consume: F)
where
    F: 'a
        + FnOnce(
            &'a mut JNIEnv<'env>,
            Result<JThrowable<'a>, BridgeLayerError>,
            ConsumableExceptionError,
        ),
{
    // This could be inlined, but then we'd have one copy per unique type for
    // `F`. That's expensive in terms of code size, so we break out the
    // invariant part into a separate function.
    let ConsumableException { throwable, error } = ConsumableException::new(env, error);
    consume(env, throwable, error)
}

struct ConsumableException<'a> {
    throwable: Result<JThrowable<'a>, BridgeLayerError>,
    error: ConsumableExceptionError,
}

enum ConsumableExceptionError {
    String(String),
    Static(&'static str),
    JniError(MochiJniError),
}

impl<'env> ConsumableException<'env> {
    fn new(env: &mut JNIEnv<'env>, error: MochiJniError) -> Self {
        let (exception_type, error) = match error {
            MochiJniError::Bridge(BridgeLayerError::CallbackException(callback, exception)) => {
                let throwable = env.new_local_ref(exception.as_obj()).map(JThrowable::from);
                return ConsumableException {
                    throwable: throwable.map_err(Into::into),
                    error: format!("error in method call '{callback}'").into(),
                };
            }
            MochiJniError::Io(error) if error.kind() == std::io::ErrorKind::Other => {
                let thrown_exception = error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<ThrownException>())
                    .map(ThrownException::as_obj);

                if let Some(exception) = thrown_exception {
                    return ConsumableException {
                        throwable: env
                            .new_local_ref::<&JObject>(exception.as_ref())
                            .map(Into::into)
                            .map_err(Into::into),
                        error: "error in callback".into(),
                    };
                }
                (ClassName("java.io.IOException"), MochiJniError::Io(error))
            }

            MochiJniError::Protocol(MochiProtocolError::ApplicationCallbackError(
                callback,
                exception,
            )) if <dyn Error>::is::<ThrownException>(&*exception) => {
                // The usual way to write this code would be to match on the result of Error::downcast.
                // However, the "failure" result, which is intended to return the original type back,
                // only supports Send and Sync as additional traits. For anything else, we have to test first.
                let exception =
                    <dyn Error>::downcast::<ThrownException>(exception).expect("just checked");
                return Self::new(
                    env,
                    MochiJniError::Bridge(BridgeLayerError::CallbackException(
                        callback, *exception,
                    )),
                );
            }

            MochiJniError::Protocol(MochiProtocolError::UntrustedIdentity(ref addr)) => {
                let throwable =
                    env.new_string(addr.name())
                        .map_err(Into::into)
                        .and_then(|addr_name| {
                            new_instance(
                                env,
                                ClassName(
                                    "org.mochi.libmochi.protocol.UntrustedIdentityException",
                                ),
                                jni_args!((addr_name => java.lang.String) -> void),
                            )
                        });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Protocol(MochiProtocolError::SessionNotFound(ref addr)) => {
                let throwable = protocol_address_to_jobject(env, addr)
                    .and_then(|addr_object| Ok((addr_object, env.new_string(error.to_string())?)))
                    .and_then(|(addr_object, message)| {
                        new_instance(
                            env,
                            ClassName("org.mochi.libmochi.protocol.NoSessionException"),
                            jni_args!((
                            addr_object => org.mochi.libmochi.protocol.MochiProtocolAddress,
                            message => java.lang.String,
                        ) -> void),
                        )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Protocol(MochiProtocolError::InvalidRegistrationId(
                ref addr,
                _value,
            )) => {
                let throwable = protocol_address_to_jobject(env, addr)
                    .and_then(|addr_object| Ok((addr_object, env.new_string(error.to_string())?)))
                    .and_then(|(addr_object, message)| {
                        new_instance(
                            env,
                            ClassName(
                                "org.mochi.libmochi.protocol.InvalidRegistrationIdException",
                            ),
                            jni_args!((
                            addr_object => org.mochi.libmochi.protocol.MochiProtocolAddress,
                            message => java.lang.String,
                        ) -> void),
                        )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Protocol(MochiProtocolError::InvalidSenderKeySession {
                distribution_id,
            }) => {
                let throwable = distribution_id
                    .convert_into(env)
                    .and_then(|distribution_id_obj| {
                        Ok((distribution_id_obj, env.new_string(error.to_string())?))
                    })
                    .and_then(|(distribution_id_obj, message)| {
                        new_instance(
                        env,
                        ClassName(
                            "org.mochi.libmochi.protocol.groups.InvalidSenderKeySessionException",
                        ),
                        jni_args!((
                            distribution_id_obj => java.util.UUID,
                            message => java.lang.String,
                        ) -> void),
                    )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Protocol(MochiProtocolError::FingerprintVersionMismatch(
                theirs,
                ours,
            )) => {
                let throwable = new_instance(
                env,
                ClassName(
                    "org.mochi.libmochi.protocol.fingerprint.FingerprintVersionMismatchException",
                ),
                jni_args!((theirs as jint => int, ours as jint => int) -> void),
            );

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Protocol(MochiProtocolError::SealedSenderSelfSend) => {
                let throwable = new_instance(
                    env,
                    ClassName("org.mochi.libmochi.metadata.SelfSendException"),
                    jni_args!(() -> void),
                );

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Cdsi(CdsiError::RateLimited { retry_after }) => {
                let retry_after_seconds = retry_after
                    .as_secs()
                    .try_into()
                    .expect("duration < lifetime of the universe");
                let throwable = new_instance(
                    env,
                    ClassName("org.mochi.libmochi.net.RetryLaterException"),
                    jni_args!((retry_after_seconds => long) -> void),
                );

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Bridge(BridgeLayerError::UnexpectedPanic(_))
            | MochiJniError::Bridge(BridgeLayerError::BadJniParameter(_))
            | MochiJniError::Bridge(BridgeLayerError::UnexpectedJniResultType(_, _)) => {
                // java.lang.AssertionError has a slightly different signature.
                let throwable = env
                    .new_string(error.to_string())
                    .map_err(BridgeLayerError::from)
                    .and_then(|message| {
                        new_instance(
                            env,
                            ClassName("java.lang.AssertionError"),
                            jni_args!((message => java.lang.Object) -> void),
                        )
                    });

                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }

            MochiJniError::Bridge(BridgeLayerError::NullPointer(_)) => {
                (ClassName("java.lang.NullPointerException"), error)
            }

            MochiJniError::Protocol(MochiProtocolError::InvalidState(_, _)) => {
                (ClassName("java.lang.IllegalStateException"), error)
            }

            MochiJniError::Protocol(MochiProtocolError::InvalidArgument(_))
            | MochiJniError::MochiCrypto(MochiCryptoError::UnknownAlgorithm(_, _))
            | MochiJniError::MochiCrypto(MochiCryptoError::InvalidInputSize)
            | MochiJniError::MochiCrypto(MochiCryptoError::InvalidNonceSize)
            | MochiJniError::Bridge(BridgeLayerError::BadArgument(_))
            | MochiJniError::Bridge(BridgeLayerError::IncorrectArrayLength { .. }) => {
                (ClassName("java.lang.IllegalArgumentException"), error)
            }

            MochiJniError::Bridge(BridgeLayerError::IntegerOverflow(_))
            | MochiJniError::Bridge(BridgeLayerError::Jni(_))
            | MochiJniError::Protocol(MochiProtocolError::ApplicationCallbackError(_, _))
            | MochiJniError::Protocol(MochiProtocolError::FfiBindingError(_))
            | MochiJniError::DeviceTransfer(DeviceTransferError::InternalError(_))
            | MochiJniError::DeviceTransfer(DeviceTransferError::KeyDecodingFailed) => {
                (ClassName("java.lang.RuntimeException"), error)
            }

            MochiJniError::Protocol(MochiProtocolError::DuplicatedMessage(_, _)) => (
                ClassName("org.mochi.libmochi.protocol.DuplicateMessageException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::InvalidPreKeyId)
            | MochiJniError::Protocol(MochiProtocolError::InvalidSignedPreKeyId)
            | MochiJniError::Protocol(MochiProtocolError::InvalidKyberPreKeyId) => (
                ClassName("org.mochi.libmochi.protocol.InvalidKeyIdException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::NoKeyTypeIdentifier)
            | MochiJniError::Protocol(MochiProtocolError::SignatureValidationFailed)
            | MochiJniError::Protocol(MochiProtocolError::BadKeyType(_))
            | MochiJniError::Protocol(MochiProtocolError::BadKeyLength(_, _))
            | MochiJniError::Protocol(MochiProtocolError::InvalidMacKeyLength(_))
            | MochiJniError::Protocol(MochiProtocolError::BadKEMKeyType(_))
            | MochiJniError::Protocol(MochiProtocolError::WrongKEMKeyType(_, _))
            | MochiJniError::Protocol(MochiProtocolError::BadKEMKeyLength(_, _))
            | MochiJniError::MochiCrypto(MochiCryptoError::InvalidKeySize) => (
                ClassName("org.mochi.libmochi.protocol.InvalidKeyException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::NoSenderKeyState { .. }) => (
                ClassName("org.mochi.libmochi.protocol.NoSessionException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::InvalidSessionStructure(_)) => (
                ClassName("org.mochi.libmochi.protocol.InvalidSessionException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::InvalidMessage(..))
            | MochiJniError::Protocol(MochiProtocolError::CiphertextMessageTooShort(_))
            | MochiJniError::Protocol(MochiProtocolError::InvalidProtobufEncoding)
            | MochiJniError::Protocol(MochiProtocolError::InvalidSealedSenderMessage(_))
            | MochiJniError::Protocol(MochiProtocolError::BadKEMCiphertextLength(_, _))
            | MochiJniError::MochiCrypto(MochiCryptoError::InvalidTag) => (
                ClassName("org.mochi.libmochi.protocol.InvalidMessageException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::UnrecognizedCiphertextVersion(_))
            | MochiJniError::Protocol(MochiProtocolError::UnrecognizedMessageVersion(_))
            | MochiJniError::Protocol(MochiProtocolError::UnknownSealedSenderVersion(_)) => (
                ClassName("org.mochi.libmochi.protocol.InvalidVersionException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::LegacyCiphertextVersion(_)) => (
                ClassName("org.mochi.libmochi.protocol.LegacyMessageException"),
                error,
            ),

            MochiJniError::Protocol(MochiProtocolError::FingerprintParsingError) => (
                ClassName("org.mochi.libmochi.protocol.fingerprint.FingerprintParsingException"),
                error,
            ),

            MochiJniError::HsmEnclave(HsmEnclaveError::HSMHandshakeError(_))
            | MochiJniError::HsmEnclave(HsmEnclaveError::HSMCommunicationError(_)) => (
                ClassName("org.mochi.libmochi.hsmenclave.EnclaveCommunicationFailureException"),
                error,
            ),
            MochiJniError::HsmEnclave(HsmEnclaveError::TrustedCodeError) => (
                ClassName("org.mochi.libmochi.hsmenclave.TrustedCodeMismatchException"),
                error,
            ),
            MochiJniError::HsmEnclave(HsmEnclaveError::InvalidPublicKeyError)
            | MochiJniError::HsmEnclave(HsmEnclaveError::InvalidCodeHashError) => {
                (ClassName("java.lang.IllegalArgumentException"), error)
            }
            MochiJniError::HsmEnclave(HsmEnclaveError::InvalidBridgeStateError) => {
                (ClassName("java.lang.IllegalStateException"), error)
            }

            MochiJniError::Enclave(EnclaveError::NoiseHandshakeError(_))
            | MochiJniError::Enclave(EnclaveError::NoiseError(_)) => (
                ClassName("org.mochi.libmochi.sgxsession.SgxCommunicationFailureException"),
                error,
            ),
            MochiJniError::Enclave(EnclaveError::AttestationError(_)) => (
                ClassName("org.mochi.libmochi.attest.AttestationFailedException"),
                error,
            ),
            MochiJniError::Enclave(EnclaveError::AttestationDataError { .. }) => (
                ClassName("org.mochi.libmochi.attest.AttestationDataException"),
                error,
            ),
            MochiJniError::Enclave(EnclaveError::InvalidBridgeStateError) => {
                (ClassName("java.lang.IllegalStateException"), error)
            }

            MochiJniError::Pin(PinError::Argon2Error(_))
            | MochiJniError::Pin(PinError::DecodingError(_))
            | MochiJniError::Pin(PinError::MrenclaveLookupError) => {
                (ClassName("java.lang.IllegalArgumentException"), error)
            }

            MochiJniError::ZkGroupDeserializationFailure(_) => (
                ClassName("org.mochi.libmochi.zkgroup.InvalidInputException"),
                error,
            ),

            MochiJniError::ZkGroupVerificationFailure(_) => (
                ClassName("org.mochi.libmochi.zkgroup.VerificationFailedException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::NicknameCannotBeEmpty) => (
                ClassName("org.mochi.libmochi.usernames.CannotBeEmptyException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::NicknameCannotStartWithDigit) => (
                ClassName("org.mochi.libmochi.usernames.CannotStartWithDigitException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::MissingSeparator) => (
                ClassName("org.mochi.libmochi.usernames.MissingSeparatorException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::BadNicknameCharacter) => (
                ClassName("org.mochi.libmochi.usernames.BadNicknameCharacterException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::NicknameTooShort) => (
                ClassName("org.mochi.libmochi.usernames.NicknameTooShortException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::NicknameTooLong) => (
                ClassName("org.mochi.libmochi.usernames.NicknameTooLongException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::DiscriminatorCannotBeEmpty) => (
                ClassName("org.mochi.libmochi.usernames.DiscriminatorCannotBeEmptyException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::DiscriminatorCannotBeZero) => (
                ClassName("org.mochi.libmochi.usernames.DiscriminatorCannotBeZeroException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::DiscriminatorCannotBeSingleDigit) => (
                ClassName(
                    "org.mochi.libmochi.usernames.DiscriminatorCannotBeSingleDigitException",
                ),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::DiscriminatorCannotHaveLeadingZeros) => (
                ClassName(
                    "org.mochi.libmochi.usernames.DiscriminatorCannotHaveLeadingZerosException",
                ),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::BadDiscriminatorCharacter) => (
                ClassName("org.mochi.libmochi.usernames.BadDiscriminatorCharacterException"),
                error,
            ),

            MochiJniError::UsernameError(UsernameError::DiscriminatorTooLarge) => (
                ClassName("org.mochi.libmochi.usernames.DiscriminatorTooLargeException"),
                error,
            ),

            MochiJniError::UsernameProofError(usernames::ProofVerificationFailure) => (
                ClassName("org.mochi.libmochi.usernames.ProofVerificationFailureException"),
                error,
            ),

            MochiJniError::UsernameLinkError(UsernameLinkError::InputDataTooLong) => (
                ClassName("org.mochi.libmochi.usernames.UsernameLinkInputDataTooLong"),
                error,
            ),

            MochiJniError::UsernameLinkError(UsernameLinkError::InvalidEntropyDataLength) => (
                ClassName("org.mochi.libmochi.usernames.UsernameLinkInvalidEntropyDataLength"),
                error,
            ),

            MochiJniError::UsernameLinkError(_) => (
                ClassName("org.mochi.libmochi.usernames.UsernameLinkInvalidLinkData"),
                error,
            ),

            MochiJniError::Io(_) => (ClassName("java.io.IOException"), error),

            #[cfg(feature = "mochi-media")]
            MochiJniError::Mp4SanitizeParse(_) | MochiJniError::WebpSanitizeParse(_) => (
                ClassName("org.mochi.libmochi.media.ParseException"),
                error,
            ),

            MochiJniError::Cdsi(CdsiError::InvalidToken) => (
                ClassName("org.mochi.libmochi.net.CdsiInvalidTokenException"),
                error,
            ),
            MochiJniError::Cdsi(
                CdsiError::InvalidResponse
                | CdsiError::ParseError
                | CdsiError::Protocol
                | CdsiError::Server { reason: _ },
            ) => (
                ClassName("org.mochi.libmochi.net.CdsiProtocolException"),
                error,
            ),

            MochiJniError::WebSocket(WebSocketServiceError::Http(_)) => (
                // In practice, all WebSocket HTTP errors come from multi-route connections, so any
                // that make it to the point of bridging are considered to have resulted from a
                // successful *connection* that then gets an error status code, and so we use
                // NetworkProtocolException instead of NetworkException. We may want to revisit
                // assuming that *here*, though.
                ClassName("org.mochi.libmochi.net.NetworkProtocolException"),
                error,
            ),

            MochiJniError::WebSocket(_) | MochiJniError::ConnectTimedOut => (
                ClassName("org.mochi.libmochi.net.NetworkException"),
                error,
            ),

            MochiJniError::Svr3(Svr3Error::RestoreFailed(tries_remaining)) => {
                let throwable = env
                    .new_string(error.to_string())
                    .map_err(BridgeLayerError::from)
                    .and_then(|message| {
                        new_instance(
                            env,
                            ClassName("org.mochi.libmochi.svr.RestoreFailedException"),
                            // The number of tries will be hard-coded by the client app
                            // to some sensible value well within the int (i32) range.
                            // Malicious server can still send an invalid value. In
                            // this case panic is the best thing we can do.
                            jni_args!((message => java.lang.String, tries_remaining
                            .try_into()
                            .expect("tries_remaining overflows int") => int) -> void),
                        )
                    });
                return ConsumableException {
                    throwable: throwable.map(Into::into),
                    error: error.into(),
                };
            }
            MochiJniError::Svr3(Svr3Error::DataMissing) => (
                ClassName("org.mochi.libmochi.svr.DataMissingException"),
                error,
            ),
            MochiJniError::Svr3(_) => (ClassName("org.mochi.libmochi.svr.SvrException"), error),

            MochiJniError::InvalidUri(_) => (ClassName("java.net.MalformedURLException"), error),

            MochiJniError::ChatService(ChatServiceError::ServiceInactive) => (
                ClassName("org.mochi.libmochi.net.ChatServiceInactiveException"),
                error,
            ),
            MochiJniError::ChatService(ChatServiceError::AppExpired) => (
                ClassName("org.mochi.libmochi.net.AppExpiredException"),
                error,
            ),
            MochiJniError::ChatService(ChatServiceError::DeviceDeregistered) => (
                ClassName("org.mochi.libmochi.net.DeviceDeregisteredException"),
                error,
            ),
            MochiJniError::ChatService(_) => (
                ClassName("org.mochi.libmochi.net.ChatServiceException"),
                error,
            ),

            MochiJniError::TestingError { exception_class } => (exception_class, error),
        };

        let throwable = env
            .new_string(error.to_string())
            .map_err(Into::into)
            .and_then(|message| {
                new_instance(
                    env,
                    exception_type,
                    jni_args!((message => java.lang.String) -> void),
                )
            });
        ConsumableException {
            throwable: throwable.map(Into::into),
            error: error.into(),
        }
    }
}

impl From<&'static str> for ConsumableExceptionError {
    fn from(value: &'static str) -> Self {
        Self::Static(value)
    }
}

impl From<String> for ConsumableExceptionError {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<MochiJniError> for ConsumableExceptionError {
    fn from(value: MochiJniError) -> Self {
        Self::JniError(value)
    }
}

impl Display for ConsumableExceptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsumableExceptionError::String(s) => Display::fmt(s, f),
            ConsumableExceptionError::Static(s) => Display::fmt(s, f),
            ConsumableExceptionError::JniError(j) => Display::fmt(j, f),
        }
    }
}

/// Translates errors into Java exceptions.
///
/// Exceptions thrown in callbacks will be rethrown; all other errors will be mapped to an
/// appropriate Java exception class and thrown.
fn throw_error(env: &mut JNIEnv, error: MochiJniError) {
    convert_to_exception(env, error, |env, throwable, error| match throwable {
        Err(failure) => log::error!("failed to create exception for {}: {}", error, failure),
        Ok(throwable) => {
            let result = env.throw(throwable);
            if let Err(failure) = result {
                log::error!("failed to throw exception for {}: {}", error, failure);
            }
        }
    });
}

#[inline(always)]
pub fn run_ffi_safe<'local, F, R>(env: &mut JNIEnv<'local>, f: F) -> R
where
    F: for<'a> FnOnce(&'a mut JNIEnv<'local>) -> Result<R, MochiJniError> + std::panic::UnwindSafe,
    R: Default,
{
    // This AssertUnwindSafe is not technically safe.
    // If we get a panic downstream, it is entirely possible the Java environment won't be usable anymore.
    // But if that's the case, we've got bigger problems!
    // So if we want to catch panics, we have to allow this.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(env))) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            throw_error(env, e);
            R::default()
        }
        Err(r) => {
            throw_error(env, BridgeLayerError::UnexpectedPanic(r).into());
            R::default()
        }
    }
}

pub unsafe fn native_handle_cast<T>(
    handle: ObjectHandle,
) -> Result<&'static mut T, BridgeLayerError> {
    /*
    Should we try testing the encoded pointer for sanity here, beyond
    being null? For example verifying that lowest bits are zero,
    highest bits are zero, greater than 64K, etc?
    */
    if handle == 0 {
        return Err(BridgeLayerError::NullPointer(None));
    }

    Ok(&mut *(handle as *mut T))
}

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`JNIEnv::call_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_method_checked<
    'input,
    'output,
    O: AsRef<JObject<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    obj: O,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_method(obj, fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

/// Calls a method and translates any thrown exceptions to
/// [`BridgeLayerError::CallbackException`].
///
/// Wraps [`JNIEnv::call_static_method`].
/// The result must have the correct type, or [`BridgeLayerError::UnexpectedJniResultType`] will be
/// returned instead.
pub fn call_static_method_checked<
    'input,
    'output,
    C: jni::descriptors::Desc<'output, JClass<'input>>,
    R: TryFrom<JValueOwned<'output>>,
    const LEN: usize,
>(
    env: &mut JNIEnv<'output>,
    cls: C,
    fn_name: &'static str,
    args: JniArgs<R, LEN>,
) -> Result<R, BridgeLayerError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_static_method(cls, fn_name, args.sig, &args.args);
    check_exceptions_and_convert_result(env, fn_name, result)
}

fn check_exceptions_and_convert_result<'output, R: TryFrom<JValueOwned<'output>>>(
    env: &mut JNIEnv<'output>,
    fn_name: &'static str,
    result: jni::errors::Result<JValueOwned<'output>>,
) -> Result<R, BridgeLayerError> {
    let throwable = env.exception_occurred()?;
    if **throwable == *JObject::null() {
        let result = result?;
        let type_name = result.type_name();
        result
            .try_into()
            .map_err(|_| BridgeLayerError::UnexpectedJniResultType(fn_name, type_name))
    } else {
        env.exception_clear()?;

        Err(BridgeLayerError::CallbackException(
            fn_name,
            ThrownException::new(env, throwable)?,
        ))
    }
}

/// Constructs a new object using [`JniArgs`].
///
/// Wraps [`JNIEnv::new_object`]; all arguments are the same.
pub fn new_object<'output, 'a, const LEN: usize>(
    env: &mut JNIEnv<'output>,
    cls: impl AsRef<JClass<'a>>,
    args: JniArgs<(), LEN>,
) -> jni::errors::Result<JObject<'output>> {
    env.new_object(cls.as_ref(), args.sig, &args.args)
}

/// Looks up a class by name and constructs a new instance using [`new_object`].
pub fn new_instance<'output, const LEN: usize>(
    env: &mut JNIEnv<'output>,
    class_name: ClassName<'_>,
    args: JniArgs<(), LEN>,
) -> Result<JObject<'output>, BridgeLayerError> {
    let class = find_class(env, class_name)?;
    new_object(env, class, args).map_err(Into::into)
}

/// Constructs a Java object from the given boxed Rust value.
///
/// Assumes there's a corresponding constructor that takes a single `long` to represent the address.
pub fn jobject_from_native_handle<'a>(
    env: &mut JNIEnv<'a>,
    class_name: ClassName<'_>,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, BridgeLayerError> {
    let class = find_class(env, class_name)?;
    Ok(new_object(
        env,
        class,
        jni_args!((boxed_handle => long) -> void),
    )?)
}

/// Constructs a Java MochiProtocolAddress from a ProtocolAddress value.
///
/// A convenience wrapper around `jobject_from_native_handle` for MochiProtocolAddress.
fn protocol_address_to_jobject<'a>(
    env: &mut JNIEnv<'a>,
    address: &ProtocolAddress,
) -> Result<JObject<'a>, BridgeLayerError> {
    let handle = address.clone().convert_into(env)?;
    jobject_from_native_handle(
        env,
        ClassName("org.mochi.libmochi.protocol.MochiProtocolAddress"),
        handle,
    )
}

/// Verifies that a Java object is a non-`null` instance of the given class.
pub fn check_jobject_type(
    env: &mut JNIEnv,
    obj: &JObject,
    class_name: ClassName<'static>,
) -> Result<(), BridgeLayerError> {
    if obj.is_null() {
        return Err(BridgeLayerError::NullPointer(Some(class_name.0)));
    }

    let class = find_class(env, class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(BridgeLayerError::BadJniParameter(class_name.0));
    }

    Ok(())
}

/// Calls a method, then clones the Rust value from the result.
///
/// The method is assumed to return a type with a `long unsafeHandle` field,
/// which in turn must hold a raw pointer produced from a boxed Rust value.
pub fn get_object_with_native_handle<T: 'static + Clone, const LEN: usize>(
    env: &mut JNIEnv,
    store_obj: &JObject,
    callback_args: JniArgs<JObject<'_>, LEN>,
    callback_fn: &'static str,
) -> Result<Option<T>, MochiJniError> {
    env.with_local_frame(64, |env| -> MochiJniResult<Option<T>> {
        let obj = call_method_checked(
            env,
            store_obj,
            callback_fn,
            callback_args.for_nested_frame(),
        )?;
        if obj.is_null() {
            return Ok(None);
        }

        let handle: jlong = env
            .get_field(obj, "unsafeHandle", jni_signature!(long))?
            .try_into()?;
        if handle == 0 {
            return Ok(None);
        }

        let object = unsafe { native_handle_cast::<T>(handle)? };
        Ok(Some(object.clone()))
    })
}

/// Calls a method, then serializes the result.
///
/// The method is assumed to return a type with a `byte[] serialize()` method.
pub fn get_object_with_serialization<const LEN: usize>(
    env: &mut JNIEnv,
    store_obj: &JObject,
    callback_args: JniArgs<JObject<'_>, LEN>,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, MochiJniError> {
    env.with_local_frame(64, |env| -> MochiJniResult<Option<Vec<u8>>> {
        let obj = call_method_checked(
            env,
            store_obj,
            callback_fn,
            callback_args.for_nested_frame(),
        )?;

        if obj.is_null() {
            return Ok(None);
        }

        let bytes: JByteArray =
            call_method_checked(env, obj, "serialize", jni_args!(() -> [byte]))?.into();

        Ok(Some(env.convert_byte_array(bytes)?))
    })
}

/// Like [CiphertextMessage], but non-owning.
///
/// Java has an interface for CiphertextMessage instead of an opaque handle, so we need to do extra
/// work to bridge it back to Rust.
#[derive(Clone, Copy)]
pub enum CiphertextMessageRef<'a> {
    MochiMessage(&'a MochiMessage),
    PreKeyMochiMessage(&'a PreKeyMochiMessage),
    SenderKeyMessage(&'a SenderKeyMessage),
    PlaintextContent(&'a PlaintextContent),
}

impl<'a> CiphertextMessageRef<'a> {
    pub fn message_type(self) -> CiphertextMessageType {
        match self {
            CiphertextMessageRef::MochiMessage(_) => CiphertextMessageType::Whisper,
            CiphertextMessageRef::PreKeyMochiMessage(_) => CiphertextMessageType::PreKey,
            CiphertextMessageRef::SenderKeyMessage(_) => CiphertextMessageType::SenderKey,
            CiphertextMessageRef::PlaintextContent(_) => CiphertextMessageType::Plaintext,
        }
    }

    pub fn serialize(self) -> &'a [u8] {
        match self {
            CiphertextMessageRef::MochiMessage(x) => x.serialized(),
            CiphertextMessageRef::PreKeyMochiMessage(x) => x.serialized(),
            CiphertextMessageRef::SenderKeyMessage(x) => x.serialized(),
            CiphertextMessageRef::PlaintextContent(x) => x.serialized(),
        }
    }
}

/// Used by [`bridge_handle_fns`](crate::support::bridge_handle_fns).
///
/// Not intended to be invoked directly.
#[macro_export]
macro_rules! jni_bridge_handle_destroy {
    ( $typ:ty as $jni_name:ident ) => {
        ::paste::paste! {
            #[export_name = concat!(
                env!("LIBMOCHI_BRIDGE_FN_PREFIX_JNI"),
                stringify!($jni_name),
                "_1Destroy"
            )]
            #[allow(non_snake_case)]
            pub unsafe extern "C" fn [<__bridge_handle_jni_ $jni_name _destroy>](
                _env: ::jni::JNIEnv,
                _class: ::jni::objects::JClass,
                handle: $crate::jni::ObjectHandle,
            ) {
                if handle != 0 {
                    let _boxed_value = Box::from_raw(handle as *mut $typ);
                }
            }
        }
    };
}

/// A wrapper around a cloned [`JNIEnv`] that forces scoped use.
///
/// This sidesteps the safety issues with [`JNIEnv::unsafe_clone`] as long as an environment from an
/// outer frame is not used within an inner frame. (Really, this same condition makes `unsafe_clone`
/// safe as well, but using `EnvHandle` is a good reminder since it *only* allows scoped access.)
struct EnvHandle<'a> {
    env: JNIEnv<'a>,
}

impl<'a> EnvHandle<'a> {
    fn new(env: &JNIEnv<'a>) -> Self {
        Self {
            env: unsafe { env.unsafe_clone() },
        }
    }

    /// See [`JNIEnv::with_local_frame`].
    fn with_local_frame<F, T, E>(&mut self, capacity: i32, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut JNIEnv<'_>) -> Result<T, E>,
        E: From<jni::errors::Error>,
    {
        self.env.with_local_frame(capacity, f)
    }
}

/// A helper to convert a primitive value, like `int`, to its boxed types, like `Integer`.
///
/// A value that's already an object will be unchanged. A `void` "value" will be converted to
/// `null`.
fn box_primitive_if_needed<'a>(
    env: &mut JNIEnv<'a>,
    value: JValueOwned<'a>,
) -> Result<JObject<'a>, BridgeLayerError> {
    match value {
        JValueOwned::Object(object) => Ok(object),
        JValueOwned::Byte(v) => new_instance(
            env,
            ClassName("java.lang.Byte"),
            jni_args!((v => byte) -> void),
        ),
        JValueOwned::Char(v) => new_instance(
            env,
            ClassName("java.lang.Character"),
            jni_args!((v => char) -> void),
        ),
        JValueOwned::Short(v) => new_instance(
            env,
            ClassName("java.lang.Short"),
            jni_args!((v => short) -> void),
        ),
        JValueOwned::Int(v) => new_instance(
            env,
            ClassName("java.lang.Integer"),
            jni_args!((v => int) -> void),
        ),
        JValueOwned::Long(v) => new_instance(
            env,
            ClassName("java.lang.Long"),
            jni_args!((v => long) -> void),
        ),
        JValueOwned::Bool(v) => new_instance(
            env,
            ClassName("java.lang.Boolean"),
            jni_args!((v != 0 => boolean) -> void),
        ),
        JValueOwned::Float(v) => new_instance(
            env,
            ClassName("java.lang.Float"),
            jni_args!((v => float) -> void),
        ),
        JValueOwned::Double(v) => new_instance(
            env,
            ClassName("java.lang.Double"),
            jni_args!((v => double) -> void),
        ),
        JValueOwned::Void => Ok(JObject::null()),
    }
}
