/*
 * Copyright 2026 open-gm-jca contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.open.jgm.pki.ca.cert.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

public class SM2PublicKey extends BCECPublicKey {
    public static final ASN1ObjectIdentifier ID_SM2_PUBKEY_PARAM = new ASN1ObjectIdentifier("1.2.156.10197.1.301");

    private boolean withCompression;

    public SM2PublicKey(BCECPublicKey key) {
        super(key.getAlgorithm(), key);
        this.withCompression = false;
    }

    public SM2PublicKey(String algorithm, BCECPublicKey key) {
        super(algorithm, key);
        this.withCompression = false;
    }

    @Override
    public byte[] getEncoded() {
        ASN1OctetString p = ASN1OctetString.getInstance(
            new X9ECPoint(getQ(), withCompression).toASN1Primitive());

        // stored curve is null if ImplicitlyCa
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ID_SM2_PUBKEY_PARAM),
            p.getOctets());

        return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
    }

    @Override
    public void setPointFormat(String style) {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }
}
