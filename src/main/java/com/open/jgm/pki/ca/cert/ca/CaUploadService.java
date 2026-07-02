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

package com.open.jgm.pki.ca.cert.ca;

import com.open.jgm.pki.ca.cert.ca.dto.CaUploadRequest;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.exception.CertException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Base64;
import java.util.Enumeration;

/**
 * T08：解析上传的 P12 / PEM，封装为 {@link CaIdentity} 并注册到 {@link CaProvider}。
 * <p>
 * 算法推断：
 * <ul>
 *   <li>{@code RSAPrivateKey}            → RSA</li>
 *   <li>{@code ECPrivateKey} + SM2 曲线  → SM2</li>
 *   <li>{@code ECPrivateKey} + 其它曲线  → ECC（curve 取自 ECParameterSpec 名称或用户指定）</li>
 * </ul>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CaUploadService {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** SM2 推荐曲线 OID（GM/T 0003） */
    private static final String SM2_CURVE_OID = "1.2.156.10197.1.301";

    private final CaProvider caProvider;

    public CaIdentity upload(CaUploadRequest req, MultipartFile multipart) {
        Parsed parsed;
        if (multipart != null && !multipart.isEmpty()) {
            parsed = parseP12(readBytes(multipart), req.getP12Password());
        } else if (req.getP12Base64() != null && !req.getP12Base64().isBlank()) {
            parsed = parseP12(Base64.getDecoder().decode(req.getP12Base64()), req.getP12Password());
        } else if (req.getCertPem() != null && req.getPrivateKeyPem() != null) {
            parsed = parsePem(req.getCertPem(), req.getPrivateKeyPem());
        } else {
            throw new CertException("必须提供 P12（multipart/base64）或 PEM（certPem + privateKeyPem）");
        }

        Algorithm algo = detectAlgorithm(parsed.privateKey);
        String curve = req.getCurve();
        if (algo == Algorithm.ECC && (curve == null || curve.isBlank())) {
            curve = detectEccCurveName(parsed.privateKey);
        }

        byte[] subCaDer;
        try {
            subCaDer = parsed.cert.getEncoded();
        } catch (Exception e) {
            throw new CertException("子 CA 证书编码失败", e);
        }
        byte[] subKeyPkcs8 = parsed.privateKey.getEncoded();

        byte[] rootDer = null;
        if (req.getRootCertPem() != null && !req.getRootCertPem().isBlank()) {
            try {
                rootDer = parseCertPem(req.getRootCertPem()).getEncoded();
            } catch (Exception e) {
                throw new CertException("根 CA 证书解析失败", e);
            }
        }

        CaIdentity draft = new CaIdentity(
                null, req.getName(), algo, curve,
                subCaDer, subKeyPkcs8, rootDer, false, System.currentTimeMillis());
        return caProvider.register(draft);
    }

    // ──────────────────────────────────────────────────────────
    // P12 / PEM 解析
    // ──────────────────────────────────────────────────────────

    private static byte[] readBytes(MultipartFile f) {
        try {
            return f.getBytes();
        } catch (IOException e) {
            throw new CertException("读取上传文件失败", e);
        }
    }

    private Parsed parseP12(byte[] p12Bytes, String password) {
        char[] pwd = (password == null ? "" : password).toCharArray();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", BC);
            ks.load(new ByteArrayInputStream(p12Bytes), pwd);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!ks.isKeyEntry(alias)) {
                    continue;
                }
                Key key = ks.getKey(alias, pwd);
                if (!(key instanceof PrivateKey priv)) {
                    continue;
                }
                Certificate c = ks.getCertificate(alias);
                if (!(c instanceof X509Certificate x509)) {
                    continue;
                }
                return new Parsed(x509, priv);
            }
            throw new CertException("P12 中未找到带私钥的证书条目");
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("P12 解析失败：" + e.getMessage(), e);
        }
    }

    private Parsed parsePem(String certPem, String keyPem) {
        X509Certificate cert = parseCertPem(certPem);
        PrivateKey key = parsePrivateKeyPem(keyPem);
        return new Parsed(cert, key);
    }

    private X509Certificate parseCertPem(String pem) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
            return (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new CertException("证书 PEM 解析失败：" + e.getMessage(), e);
        }
    }

    private PrivateKey parsePrivateKeyPem(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BC);
            if (obj instanceof PEMKeyPair pkp) {
                return conv.getKeyPair(pkp).getPrivate();
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return conv.getPrivateKey(pki);
            }
            throw new CertException("不支持的私钥 PEM 类型: " + (obj == null ? "null" : obj.getClass().getName()));
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("私钥 PEM 解析失败：" + e.getMessage(), e);
        }
    }

    // ──────────────────────────────────────────────────────────
    // 算法 / 曲线检测
    // ──────────────────────────────────────────────────────────

    private static Algorithm detectAlgorithm(PrivateKey key) {
        String algo = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algo)) {
            return Algorithm.RSA;
        }
        if ("EC".equalsIgnoreCase(algo) || "ECDSA".equalsIgnoreCase(algo)) {
            return isSm2Curve(key) ? Algorithm.SM2 : Algorithm.ECC;
        }
        throw new CertException("不支持的私钥算法: " + algo);
    }

    private static boolean isSm2Curve(PrivateKey key) {
        if (!(key instanceof ECPrivateKey ec)) {
            return false;
        }
        ECParameterSpec params = ec.getParams();
        // 通过 byte 表示比较曲线 OID 比较脆弱；放宽到 BC 私有 API 字符串名称匹配
        String spec = params == null ? "" : params.toString();
        return spec.contains("sm2") || spec.contains("SM2")
                || spec.contains(SM2_CURVE_OID) || spec.contains("wapip192v1");
    }

    private static String detectEccCurveName(PrivateKey key) {
        if (key instanceof org.bouncycastle.jce.interfaces.ECPrivateKey bcKey) {
            org.bouncycastle.jce.spec.ECParameterSpec spec = bcKey.getParameters();
            if (spec instanceof org.bouncycastle.jce.spec.ECNamedCurveParameterSpec named) {
                return named.getName();
            }
        }
        return "prime256v1";
    }

    // ──────────────────────────────────────────────────────────

    private record Parsed(X509Certificate cert, PrivateKey privateKey) {}
}
