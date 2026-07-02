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

package com.open.jgm.pki.ca.cert.util;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.HexUtil;
import com.open.jgm.pki.ca.cert.dto.response.CertDetailResult;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * 证书解析工具：从 X.509 证书提取 DN、序列号、有效期等可读字段。
 */
@Slf4j
public final class CertParseUtil {

    private CertParseUtil() {}

    /**
     * 将 Base64 DER 或 PEM 证书字符串解析为 {@link CertDetailResult}。
     */
    public static CertDetailResult parse(String base64Cert) {
        X509Certificate x509 = SM2CertUtil.convertToX509Certificate(base64Cert);
        CertDetailResult result = new CertDetailResult();

        // ── Subject DN ──
        String subjectDn = x509.getSubjectDN().getName();
        if (StringUtils.isNotBlank(subjectDn)) {
            for (String part : subjectDn.split(",")) {
                String[] kv = part.trim().split("=", 2);
                if (kv.length < 2) continue;
                switch (kv[0].trim().toUpperCase()) {
                    case "CN"     -> result.setUniversalName(kv[1]);
                    case "O"      -> result.setOrganization(kv[1]);
                    case "OU"     -> result.setOrganizationUnit(kv[1]);
                    case "C"      -> result.setCountry(kv[1]);
                    case "ST"     -> result.setProvince(kv[1]);
                    case "L"      -> result.setCity(kv[1]);
                    case "STREET" -> result.setStreet(kv[1]);
                    case "E"      -> result.setEmail(kv[1]);
                }
            }
        }

        // ── Cert bytes ──
        try {
            result.setCert(Base64.encode(x509.getEncoded()));
        } catch (CertificateEncodingException e) {
            log.error("解析证书内容出错", e);
        }

        // ── Issuer CN ──
        String issuerDn = x509.getIssuerDN().getName();
        if (StringUtils.isNotBlank(issuerDn)) {
            result.setIssueOrg(extractCn(issuerDn));
        }

        // ── Validity ──
        result.setCertValidStartTime(x509.getNotBefore());
        result.setCertValidEndTime(x509.getNotAfter());

        // ── Serial number ──
        try {
            byte[] serialBytes = x509.getSerialNumber().toByteArray();
            if (serialBytes.length == 8) {
                byte[] padded = new byte[9];
                System.arraycopy(serialBytes, 0, padded, 1, 8);
                serialBytes = padded;
            }
            result.setSerialNumberHex(HexUtil.encodeHexStr(serialBytes, true));
        } catch (Exception e) {
            log.error("解析证书序列号出错", e);
        }

        // ── T22: 签名/公钥算法 & v3 扩展 ──
        try {
            result.setSignatureAlgorithm(x509.getSigAlgName());
            java.security.PublicKey pub = x509.getPublicKey();
            result.setPublicKeyAlgorithm(pub.getAlgorithm());
            result.setPublicKeyBits(publicKeyBits(pub));
            result.setExtensions(X509ExtensionParser.parse(x509));
        } catch (Exception e) {
            log.warn("解析 v3 扩展或公钥信息失败", e);
        }

        return result;
    }

    private static Integer publicKeyBits(java.security.PublicKey pub) {
        if (pub instanceof java.security.interfaces.RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (pub instanceof java.security.interfaces.ECPublicKey ec) {
            java.security.spec.ECParameterSpec spec = ec.getParams();
            return spec == null ? null : spec.getCurve().getField().getFieldSize();
        }
        if (pub instanceof java.security.interfaces.DSAPublicKey dsa) {
            return dsa.getParams() == null ? null : dsa.getParams().getP().bitLength();
        }
        return null;
    }

    private static String extractCn(String dn) {
        int start = dn.indexOf("CN=");
        if (start == -1) return null;
        start += 3;
        int end = dn.indexOf(",", start);
        return end == -1 ? dn.substring(start) : dn.substring(start, end);
    }
}
