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

package com.open.jgm.pki.ca.cert.envelope;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * T17-T19：数字信封涉及到的 OID 常量。
 * <p>
 * 国密 OID 引自 GM/T 0006-2012；通用 OID 引自 RFC 3370 / PKCS 系列。
 */
public final class GmEnvelopeOids {

    private GmEnvelopeOids() {}

    /** SM4 块加密 - CBC 模式（GM/T 0006）。 */
    public static final ASN1ObjectIdentifier SM4_CBC = new ASN1ObjectIdentifier("1.2.156.10197.1.104.2");

    /** SM2 公钥加密算法（数据加密；GM/T 0006）。 */
    public static final ASN1ObjectIdentifier SM2_ENCRYPT = new ASN1ObjectIdentifier("1.2.156.10197.1.301.3");

    /** PKCS#1 v1.5 RSA 加密（RFC 8017）。 */
    public static final ASN1ObjectIdentifier RSA_PKCS1 = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");

    /** AES-128-CBC（NIST OID）。 */
    public static final ASN1ObjectIdentifier AES_128_CBC = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2");
}
