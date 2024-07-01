//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.zkgroup.receipts;

import static org.mochi.libmochi.internal.FilterExceptions.filterExceptions;
import static org.mochi.libmochi.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.zkgroup.InvalidInputException;
import org.mochi.libmochi.zkgroup.ServerPublicParams;
import org.mochi.libmochi.zkgroup.VerificationFailedException;

public class ClientZkReceiptOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkReceiptOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  public ReceiptCredentialRequestContext createReceiptCredentialRequestContext(
      ReceiptSerial receiptSerial) throws VerificationFailedException {
    return createReceiptCredentialRequestContext(new SecureRandom(), receiptSerial);
  }

  public ReceiptCredentialRequestContext createReceiptCredentialRequestContext(
      SecureRandom secureRandom, ReceiptSerial receiptSerial) throws VerificationFailedException {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverPublicParams.guardedMap(
            (serverPublicParams) ->
                Native.ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
                    serverPublicParams, random, receiptSerial.getInternalContentsForJNI()));

    try {
      return new ReceiptCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ReceiptCredential receiveReceiptCredential(
      ReceiptCredentialRequestContext receiptCredentialRequestContext,
      ReceiptCredentialResponse receiptCredentialResponse)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverPublicParams.guardedMapChecked(
                    (publicParams) ->
                        Native.ServerPublicParams_ReceiveReceiptCredential(
                            publicParams,
                            receiptCredentialRequestContext.getInternalContentsForJNI(),
                            receiptCredentialResponse.getInternalContentsForJNI())));
    try {
      return new ReceiptCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ReceiptCredentialPresentation createReceiptCredentialPresentation(
      ReceiptCredential receiptCredential) throws VerificationFailedException {
    return createReceiptCredentialPresentation(new SecureRandom(), receiptCredential);
  }

  public ReceiptCredentialPresentation createReceiptCredentialPresentation(
      SecureRandom secureRandom, ReceiptCredential receiptCredential)
      throws VerificationFailedException {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverPublicParams.guardedMap(
            (publicParams) ->
                Native.ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
                    publicParams, random, receiptCredential.getInternalContentsForJNI()));
    try {
      return new ReceiptCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
