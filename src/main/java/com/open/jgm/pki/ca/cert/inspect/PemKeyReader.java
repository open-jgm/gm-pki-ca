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

package com.open.jgm.pki.ca.cert.inspect;

import com.open.jgm.pki.ca.cert.exception.CertException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * 共享 PEM/证书读取助手。
 */
public final class PemKeyReader {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private PemKeyReader() {}

    public static X509Certificate readCert(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new CertException("证书内容不能为空");
        }
        String s = raw.trim();
        try {
            byte[] der;
            if (s.startsWith("-----BEGIN")) {
                der = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            } else {
                der = Base64.getDecoder().decode(s);
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CertException("证书解析失败: " + e.getMessage(), e);
        }
    }

    /**
     * 读取私钥 PEM。支持：
     * <ul>
     *   <li>PKCS#8 明文 ({@code -----BEGIN PRIVATE KEY-----})</li>
     *   <li>PKCS#8 加密 ({@code -----BEGIN ENCRYPTED PRIVATE KEY-----})</li>
     *   <li>RSA PEM ({@code -----BEGIN RSA PRIVATE KEY-----})</li>
     *   <li>EC PEM ({@code -----BEGIN EC PRIVATE KEY-----})</li>
     *   <li>OpenSSL 加密 (PEMEncryptedKeyPair)</li>
     * </ul>
     */
    public static PrivateKey readPrivateKey(String pem, String password) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BC);
            char[] pwdChars = password == null ? new char[0] : password.toCharArray();

            if (obj instanceof PEMEncryptedKeyPair enc) {
                obj = enc.decryptKeyPair(new JcePEMDecryptorProviderBuilder().setProvider(BC).build(pwdChars));
            }
            if (obj instanceof PEMKeyPair pkp) {
                return conv.getKeyPair(pkp).getPrivate();
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return conv.getPrivateKey(pki);
            }
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo epki) {
                var decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BC).build(pwdChars);
                return conv.getPrivateKey(epki.decryptPrivateKeyInfo(decryptor));
            }
            throw new CertException("不支持的私钥 PEM 类型: " + (obj == null ? "null" : obj.getClass().getName()));
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("私钥 PEM 解析失败: " + e.getMessage(), e);
        }
    }
}
