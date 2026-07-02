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

import cn.hutool.core.util.HexUtil;
import com.open.jgm.pki.ca.cert.dto.response.CertExtensionsView;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * T22：解析 X.509 v3 扩展项。集中各扩展的 OID 到可读名映射。
 */
@Slf4j
public final class X509ExtensionParser {

    private X509ExtensionParser() {}

    /** KeyUsage 位 → 可读名（RFC 5280 顺序）。 */
    private static final String[] KU_NAMES = {
            "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
    };

    /** ExtendedKeyUsage OID → 可读名。 */
    private static final Map<String, String> EKU_NAMES = new LinkedHashMap<>();
    static {
        EKU_NAMES.put(KeyPurposeId.id_kp_serverAuth.getId(),       "serverAuth");
        EKU_NAMES.put(KeyPurposeId.id_kp_clientAuth.getId(),       "clientAuth");
        EKU_NAMES.put(KeyPurposeId.id_kp_codeSigning.getId(),      "codeSigning");
        EKU_NAMES.put(KeyPurposeId.id_kp_emailProtection.getId(),  "emailProtection");
        EKU_NAMES.put(KeyPurposeId.id_kp_timeStamping.getId(),     "timeStamping");
        EKU_NAMES.put(KeyPurposeId.id_kp_OCSPSigning.getId(),      "ocspSigning");
        EKU_NAMES.put(KeyPurposeId.anyExtendedKeyUsage.getId(),    "anyExtendedKeyUsage");
    }

    public static CertExtensionsView parse(X509Certificate x509) {
        CertExtensionsView v = new CertExtensionsView();
        v.setKeyUsages(parseKeyUsage(x509));
        v.setExtendedKeyUsages(parseExtendedKeyUsage(x509));
        v.setSubjectAltNames(parseSubjectAltName(x509));
        v.setAuthorityKeyIdentifierHex(parseAki(x509));
        v.setSubjectKeyIdentifierHex(parseSki(x509));
        applyBasicConstraints(v, x509);
        return v;
    }

    // ──────────────────────────────────────────────────────────

    private static List<String> parseKeyUsage(X509Certificate x509) {
        boolean[] bits = x509.getKeyUsage();
        if (bits == null) return null;
        List<String> out = new ArrayList<>();
        for (int i = 0; i < bits.length && i < KU_NAMES.length; i++) {
            if (bits[i]) out.add(KU_NAMES[i]);
        }
        return out.isEmpty() ? null : out;
    }

    private static List<String> parseExtendedKeyUsage(X509Certificate x509) {
        try {
            List<String> oids = x509.getExtendedKeyUsage();
            if (oids == null || oids.isEmpty()) return null;
            List<String> out = new ArrayList<>(oids.size());
            for (String oid : oids) {
                out.add(EKU_NAMES.getOrDefault(oid, oid));
            }
            return out;
        } catch (Exception e) {
            log.warn("解析 ExtendedKeyUsage 失败", e);
            return null;
        }
    }

    private static List<String> parseSubjectAltName(X509Certificate x509) {
        try {
            byte[] der = x509.getExtensionValue(Extension.subjectAlternativeName.getId());
            if (der == null) return null;
            byte[] inner = ASN1OctetString.getInstance(der).getOctets();
            GeneralNames names = GeneralNames.getInstance(ASN1Primitive.fromByteArray(inner));
            if (names == null || names.getNames().length == 0) return null;
            List<String> out = new ArrayList<>();
            for (GeneralName g : names.getNames()) {
                out.add(formatGeneralName(g));
            }
            return out;
        } catch (IOException e) {
            log.warn("解析 SubjectAltName 失败", e);
            return null;
        }
    }

    private static String formatGeneralName(GeneralName g) {
        return switch (g.getTagNo()) {
            case GeneralName.dNSName -> "dns:" + g.getName();
            case GeneralName.iPAddress -> "ip:" + formatIpAddress(g);
            case GeneralName.rfc822Name -> "email:" + g.getName();
            case GeneralName.uniformResourceIdentifier -> "uri:" + g.getName();
            case GeneralName.directoryName -> "dirName:" + g.getName();
            case GeneralName.otherName -> "other:" + g.getName();
            default -> "tag" + g.getTagNo() + ":" + g.getName();
        };
    }

    private static String formatIpAddress(GeneralName g) {
        try {
            byte[] octets = ASN1OctetString.getInstance(g.getName()).getOctets();
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (IllegalArgumentException | UnknownHostException e) {
            log.warn("解析 SubjectAltName IP 地址失败", e);
            return g.getName().toString();
        }
    }

    private static String parseAki(X509Certificate x509) {
        try {
            byte[] der = x509.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            if (der == null) return null;
            byte[] inner = ASN1OctetString.getInstance(der).getOctets();
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(inner);
            byte[] id = aki.getKeyIdentifier();
            return id == null ? null : HexUtil.encodeHexStr(id);
        } catch (Exception e) {
            log.warn("解析 AuthorityKeyIdentifier 失败", e);
            return null;
        }
    }

    private static String parseSki(X509Certificate x509) {
        try {
            byte[] der = x509.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (der == null) return null;
            byte[] inner = ASN1OctetString.getInstance(der).getOctets();
            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(inner);
            return HexUtil.encodeHexStr(ski.getKeyIdentifier());
        } catch (Exception e) {
            log.warn("解析 SubjectKeyIdentifier 失败", e);
            return null;
        }
    }

    private static void applyBasicConstraints(CertExtensionsView v, X509Certificate x509) {
        try {
            byte[] der = x509.getExtensionValue(Extension.basicConstraints.getId());
            if (der == null) return;
            byte[] inner = ASN1OctetString.getInstance(der).getOctets();
            BasicConstraints bc = BasicConstraints.getInstance(inner);
            v.setBasicConstraintsCA(bc.isCA());
            if (bc.isCA() && bc.getPathLenConstraint() != null) {
                v.setBasicConstraintsPathLen(bc.getPathLenConstraint().intValue());
            }
        } catch (Exception e) {
            log.warn("解析 BasicConstraints 失败", e);
        }
    }

    // 暴露常量便于外部使用
    public static String[] keyUsageNames() {
        return Arrays.copyOf(KU_NAMES, KU_NAMES.length);
    }
}
