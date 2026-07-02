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
import com.open.jgm.pki.ca.cert.inspect.dto.KeyInspectRequest;
import com.open.jgm.pki.ca.cert.inspect.dto.KeyInspectResult;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * T24：私钥检查 & 私钥/证书匹配校验。
 */
@Service
public class KeyInspectService {

    public KeyInspectResult inspect(KeyInspectRequest req) {
        if (req == null || req.getPrivateKeyPem() == null || req.getPrivateKeyPem().isBlank()) {
            throw new CertException("privateKeyPem 不能为空");
        }
        PrivateKey priv = PemKeyReader.readPrivateKey(req.getPrivateKeyPem(), req.getPassword());

        String algo = describeAlgorithm(priv);
        Integer bits = privateKeyBits(priv);
        String curve = privateKeyCurve(priv);

        Boolean match = null;
        String reason = null;
        if (req.getCertPemOrBase64() != null && !req.getCertPemOrBase64().isBlank()) {
            X509Certificate cert = PemKeyReader.readCert(req.getCertPemOrBase64());
            MatchResult mr = matches(priv, cert.getPublicKey());
            match = mr.ok;
            reason = mr.reason;
        }

        return KeyInspectResult.builder()
                .algorithm(algo)
                .bits(bits)
                .curve(curve)
                .matchCertificate(match)
                .mismatchReason(reason)
                .build();
    }

    // ──────────────────────────────────────────────────────────

    private static String describeAlgorithm(PrivateKey priv) {
        String a = priv.getAlgorithm();
        if ("EC".equalsIgnoreCase(a) || "ECDSA".equalsIgnoreCase(a)) {
            return isSm2(priv) ? "SM2-EC" : "EC";
        }
        return a;
    }

    private static Integer privateKeyBits(PrivateKey priv) {
        if (priv instanceof RSAPrivateKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (priv instanceof ECPrivateKey ec) {
            return ec.getParams() == null ? null : ec.getParams().getCurve().getField().getFieldSize();
        }
        return null;
    }

    private static String privateKeyCurve(PrivateKey priv) {
        if (priv instanceof BCECPrivateKey bcec) {
            var spec = bcec.getParameters();
            if (spec instanceof org.bouncycastle.jce.spec.ECNamedCurveParameterSpec named) {
                return named.getName();
            }
        }
        return null;
    }

    private static boolean isSm2(PrivateKey priv) {
        if (!(priv instanceof BCECPrivateKey bcec)) return false;
        String n = privateKeyCurve(priv);
        if (n != null && (n.equalsIgnoreCase("sm2p256v1") || n.equalsIgnoreCase("wapip192v1"))) return true;
        String spec = bcec.getParameters() == null ? "" : bcec.getParameters().toString();
        return spec.contains("sm2") || spec.contains("1.2.156.10197.1.301");
    }

    private static MatchResult matches(PrivateKey priv, PublicKey pub) {
        // 算法须同族
        String pa = priv.getAlgorithm();
        String pubA = pub.getAlgorithm();
        if (!pa.equalsIgnoreCase(pubA) && !(isEcLike(pa) && isEcLike(pubA))) {
            return new MatchResult(false, "私钥算法 " + pa + " 与证书公钥算法 " + pubA + " 不同");
        }
        if (priv instanceof RSAPrivateKey rsa && pub instanceof RSAPublicKey rpub) {
            return new MatchResult(rsa.getModulus().equals(rpub.getModulus()),
                    rsa.getModulus().equals(rpub.getModulus()) ? null : "RSA 模数不一致");
        }
        if (priv instanceof ECPrivateKey ec && pub instanceof ECPublicKey epub) {
            // 通过 d * G 计算 Q 然后比较；这里用 BouncyCastle 提供的 ECPoint 比较
            try {
                org.bouncycastle.jce.spec.ECParameterSpec bcSpec =
                        ((BCECPrivateKey) ec).getParameters();
                if (bcSpec == null) {
                    return new MatchResult(false, "无法读取 EC 私钥曲线参数");
                }
                org.bouncycastle.math.ec.ECPoint q =
                        bcSpec.getG().multiply(((BCECPrivateKey) ec).getD()).normalize();
                org.bouncycastle.math.ec.ECPoint pubPoint =
                        ((org.bouncycastle.jce.interfaces.ECPublicKey) epub).getQ();
                boolean eq = q.equals(pubPoint.normalize());
                return new MatchResult(eq, eq ? null : "EC 公钥点与私钥 d·G 不一致");
            } catch (Exception e) {
                return new MatchResult(false, "EC 匹配校验异常: " + e.getMessage());
            }
        }
        return new MatchResult(false, "不支持的密钥类型组合: " + pa + " / " + pubA);
    }

    private static boolean isEcLike(String a) {
        return "EC".equalsIgnoreCase(a) || "ECDSA".equalsIgnoreCase(a);
    }

    private record MatchResult(boolean ok, String reason) {}
}
