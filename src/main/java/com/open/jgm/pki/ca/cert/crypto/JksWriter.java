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

import com.open.jgm.pki.ca.cert.config.CertConfig;
import com.open.jgm.pki.ca.cert.exception.CertException;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * JKS（Java KeyStore）写入工具。
 * <p>
 * T03 起：作为 PEM/DER/P12 之外的第四种用户证书输出格式。
 * <ul>
 *   <li>仅支持 RSA / ECC 私钥；SM2 私钥不与默认 SunJCA 兼容，调用方应保证不传入。</li>
 *   <li>alias 固定为 "alias"，与现有 P12 输出保持一致。</li>
 *   <li>口令由调用方提供；与 P12 共用同一口令（{@link CertConfig#getP12Password()}）。</li>
 * </ul>
 */
public final class JksWriter {

    private JksWriter() {}

    /**
     * 将私钥 + 用户证书写入 JKS 字节流。
     *
     * @param privateKey 私钥（RSA / ECC）；调用方保证非 null
     * @param userCert   用户证书
     * @param password   JKS 口令（与 P12 共用）
     * @return JKS 字节
     * @throws CertException 写入失败
     */
    public static byte[] write(PrivateKey privateKey, Certificate userCert, String password) {
        if (privateKey == null || userCert == null || password == null) {
            throw new CertException("JKS 写入参数不能为 null");
        }
        try {
            char[] pwd = password.toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, pwd);
            ks.setKeyEntry("alias", privateKey, pwd, new Certificate[]{userCert});
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                ks.store(baos, pwd);
                return baos.toByteArray();
            }
        } catch (Exception e) {
            throw new CertException("JKS 序列化失败", e);
        }
    }
}
