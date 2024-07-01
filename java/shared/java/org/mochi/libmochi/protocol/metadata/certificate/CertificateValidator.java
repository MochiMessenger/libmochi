//
// Copyright 2023 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.mochi.libmochi.metadata.certificate;

import org.mochi.libmochi.internal.Native;
import org.mochi.libmochi.internal.NativeHandleGuard;
import org.mochi.libmochi.protocol.InvalidKeyException;
import org.mochi.libmochi.protocol.ecc.Curve;
import org.mochi.libmochi.protocol.ecc.ECPublicKey;

public class CertificateValidator {
  private final ECPublicKey trustRoot;

  public CertificateValidator(ECPublicKey trustRoot) {
    this.trustRoot = trustRoot;
  }

  public ECPublicKey getTrustRoot() {
    return this.trustRoot;
  }

  public void validate(SenderCertificate certificate, long validationTime)
      throws InvalidCertificateException {
    try (NativeHandleGuard certificateGuard = new NativeHandleGuard(certificate);
        NativeHandleGuard trustRootGuard = new NativeHandleGuard(trustRoot)) {
      if (!Native.SenderCertificate_Validate(
          certificateGuard.nativeHandle(), trustRootGuard.nativeHandle(), validationTime)) {
        throw new InvalidCertificateException("Validation failed");
      }
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  // VisibleForTesting
  void validate(ServerCertificate certificate) throws InvalidCertificateException {
    try {
      if (!Curve.verifySignature(
          trustRoot, certificate.getCertificate(), certificate.getSignature())) {
        throw new InvalidCertificateException("Signature failed");
      }
    } catch (InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }
}
