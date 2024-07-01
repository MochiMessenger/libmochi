//
// Copyright 2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { ProtocolAddress } from './Address';
import * as Native from '../Native';

export enum ErrorCode {
  Generic,

  DuplicatedMessage,
  SealedSenderSelfSend,
  UntrustedIdentity,
  InvalidRegistrationId,
  VerificationFailed,
  InvalidSession,
  InvalidSenderKeySession,

  NicknameCannotBeEmpty,
  CannotStartWithDigit,
  MissingSeparator,
  BadNicknameCharacter,
  NicknameTooShort,
  NicknameTooLong,
  DiscriminatorCannotBeEmpty,
  DiscriminatorCannotBeZero,
  DiscriminatorCannotBeSingleDigit,
  DiscriminatorCannotHaveLeadingZeros,
  BadDiscriminatorCharacter,
  DiscriminatorTooLarge,

  IoError,
  CdsiInvalidToken,
  InvalidUri,

  InvalidMediaInput,
  UnsupportedMediaInput,

  InputDataTooLong,
  InvalidEntropyDataLength,
  InvalidUsernameLinkEncryptedData,

  RateLimitedError,

  SvrDataMissing,
  SvrRequestFailed,
  SvrRestoreFailed,

  ChatServiceInactive,
  AppExpired,
  DeviceDelinked,

  Cancelled,
}

export class LibMochiErrorBase extends Error {
  public readonly code: ErrorCode;
  public readonly operation: string;
  readonly _addr?: string | Native.ProtocolAddress;

  constructor(
    message: string,
    name: keyof typeof ErrorCode | undefined,
    operation: string,
    extraProps?: Record<string, unknown>
  ) {
    super(message);
    // Include the dynamic check for `name in ErrorCode` in case there's a bug in the Rust code.
    if (name !== undefined && name in ErrorCode) {
      this.name = name;
      this.code = ErrorCode[name];
    } else {
      this.name = 'LibMochiError';
      this.code = ErrorCode.Generic;
    }
    this.operation = operation;
    if (extraProps !== undefined) {
      Object.assign(this, extraProps);
    }

    // Maintains proper stack trace, where our error was thrown (only available on V8)
    //   via https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this);
    }
  }

  public get addr(): ProtocolAddress | string {
    switch (this.code) {
      case ErrorCode.UntrustedIdentity:
        return this._addr as string;
      case ErrorCode.InvalidRegistrationId:
        return ProtocolAddress._fromNativeHandle(
          this._addr as Native.ProtocolAddress
        );
      default:
        throw new TypeError(`cannot get address from this error (${this})`);
    }
  }
}

export type LibMochiErrorCommon = Omit<LibMochiErrorBase, 'addr'>;

export type GenericError = LibMochiErrorCommon & {
  code: ErrorCode.Generic;
};

export type DuplicatedMessageError = LibMochiErrorCommon & {
  code: ErrorCode.DuplicatedMessage;
};

export type SealedSenderSelfSendError = LibMochiErrorCommon & {
  code: ErrorCode.SealedSenderSelfSend;
};

export type UntrustedIdentityError = LibMochiErrorCommon & {
  code: ErrorCode.UntrustedIdentity;
  addr: string;
};

export type InvalidRegistrationIdError = LibMochiErrorCommon & {
  code: ErrorCode.InvalidRegistrationId;
  addr: ProtocolAddress;
};

export type VerificationFailedError = LibMochiErrorCommon & {
  code: ErrorCode.VerificationFailed;
};

export type InvalidSessionError = LibMochiErrorCommon & {
  code: ErrorCode.InvalidSession;
};

export type InvalidSenderKeySessionError = LibMochiErrorCommon & {
  code: ErrorCode.InvalidSenderKeySession;
  distributionId: string;
};

export type NicknameCannotBeEmptyError = LibMochiErrorCommon & {
  code: ErrorCode.NicknameCannotBeEmpty;
};
export type CannotStartWithDigitError = LibMochiErrorCommon & {
  code: ErrorCode.CannotStartWithDigit;
};
export type MissingSeparatorError = LibMochiErrorCommon & {
  code: ErrorCode.MissingSeparator;
};

export type BadNicknameCharacterError = LibMochiErrorCommon & {
  code: ErrorCode.BadNicknameCharacter;
};

export type NicknameTooShortError = LibMochiErrorCommon & {
  code: ErrorCode.NicknameTooShort;
};

export type NicknameTooLongError = LibMochiErrorCommon & {
  code: ErrorCode.NicknameTooLong;
};

export type DiscriminatorCannotBeEmptyError = LibMochiErrorCommon & {
  code: ErrorCode.DiscriminatorCannotBeEmpty;
};
export type DiscriminatorCannotBeZeroError = LibMochiErrorCommon & {
  code: ErrorCode.DiscriminatorCannotBeZero;
};
export type DiscriminatorCannotBeSingleDigitError = LibMochiErrorCommon & {
  code: ErrorCode.DiscriminatorCannotBeSingleDigit;
};
export type DiscriminatorCannotHaveLeadingZerosError = LibMochiErrorCommon & {
  code: ErrorCode.DiscriminatorCannotHaveLeadingZeros;
};
export type BadDiscriminatorCharacterError = LibMochiErrorCommon & {
  code: ErrorCode.BadDiscriminatorCharacter;
};
export type DiscriminatorTooLargeError = LibMochiErrorCommon & {
  code: ErrorCode.DiscriminatorTooLarge;
};

export type InputDataTooLong = LibMochiErrorCommon & {
  code: ErrorCode.InputDataTooLong;
};

export type InvalidEntropyDataLength = LibMochiErrorCommon & {
  code: ErrorCode.InvalidEntropyDataLength;
};

export type InvalidUsernameLinkEncryptedData = LibMochiErrorCommon & {
  code: ErrorCode.InvalidUsernameLinkEncryptedData;
};

export type IoError = LibMochiErrorCommon & {
  code: ErrorCode.IoError;
};

export type CdsiInvalidTokenError = LibMochiErrorCommon & {
  code: ErrorCode.CdsiInvalidToken;
};

export type InvalidUriError = LibMochiErrorCommon & {
  code: ErrorCode.InvalidUri;
};

export type InvalidMediaInputError = LibMochiErrorCommon & {
  code: ErrorCode.InvalidMediaInput;
};

export type UnsupportedMediaInputError = LibMochiErrorCommon & {
  code: ErrorCode.UnsupportedMediaInput;
};

export type RateLimitedError = LibMochiErrorBase & {
  code: ErrorCode.RateLimitedError;
  readonly retryAfterSecs: number;
};

export type ChatServiceInactive = LibMochiErrorBase & {
  code: ErrorCode.ChatServiceInactive;
};

export type AppExpiredError = LibMochiErrorBase & {
  code: ErrorCode.AppExpired;
};

export type DeviceDelinkedError = LibMochiErrorBase & {
  code: ErrorCode.DeviceDelinked;
};

export type SvrDataMissingError = LibMochiErrorBase & {
  code: ErrorCode.SvrDataMissing;
};

export type SvrRequestFailedError = LibMochiErrorCommon & {
  code: ErrorCode.SvrRequestFailed;
};

export type SvrRestoreFailedError = LibMochiErrorCommon & {
  code: ErrorCode.SvrRestoreFailed;
  readonly triesRemaining: number;
};

export type CancellationError = LibMochiErrorCommon & {
  code: ErrorCode.Cancelled;
};

export type LibMochiError =
  | GenericError
  | DuplicatedMessageError
  | SealedSenderSelfSendError
  | UntrustedIdentityError
  | InvalidRegistrationIdError
  | VerificationFailedError
  | InvalidSessionError
  | InvalidSenderKeySessionError
  | NicknameCannotBeEmptyError
  | CannotStartWithDigitError
  | MissingSeparatorError
  | BadNicknameCharacterError
  | NicknameTooShortError
  | NicknameTooLongError
  | DiscriminatorCannotBeEmptyError
  | DiscriminatorCannotBeZeroError
  | DiscriminatorCannotBeSingleDigitError
  | DiscriminatorCannotHaveLeadingZerosError
  | BadDiscriminatorCharacterError
  | DiscriminatorTooLargeError
  | InputDataTooLong
  | InvalidEntropyDataLength
  | InvalidUsernameLinkEncryptedData
  | IoError
  | CdsiInvalidTokenError
  | InvalidUriError
  | InvalidMediaInputError
  | SvrDataMissingError
  | SvrRestoreFailedError
  | SvrRequestFailedError
  | UnsupportedMediaInputError
  | ChatServiceInactive
  | AppExpiredError
  | DeviceDelinkedError
  | CancellationError;
