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

package com.open.jgm.pki.ca.cert.dto.enums;

import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * RFC 5280 ExtendedKeyUsage 的字符串映射。
 * <p>
 * 解析大小写不敏感；未知值抛 {@link IllegalArgumentException}。
 */
public enum ExtKeyUsageType {
    SERVER_AUTH      (KeyPurposeId.id_kp_serverAuth,      "serverAuth"),
    CLIENT_AUTH      (KeyPurposeId.id_kp_clientAuth,      "clientAuth"),
    CODE_SIGNING     (KeyPurposeId.id_kp_codeSigning,     "codeSigning"),
    EMAIL_PROTECTION (KeyPurposeId.id_kp_emailProtection, "emailProtection"),
    TIME_STAMPING    (KeyPurposeId.id_kp_timeStamping,    "timeStamping"),
    OCSP_SIGNING     (KeyPurposeId.id_kp_OCSPSigning,     "ocspSigning", "OCSPSigning");

    private final KeyPurposeId purpose;
    private final String[] aliases;

    ExtKeyUsageType(KeyPurposeId purpose, String... aliases) {
        this.purpose = purpose;
        this.aliases = aliases;
    }

    public KeyPurposeId purpose() {
        return purpose;
    }

    public static ExtKeyUsageType parse(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("ExtKeyUsage 不能为 null");
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("ExtKeyUsage 不能为空");
        }
        for (ExtKeyUsageType t : values()) {
            if (t.name().equalsIgnoreCase(trimmed)) {
                return t;
            }
            for (String alias : t.aliases) {
                if (alias.equalsIgnoreCase(trimmed)) {
                    return t;
                }
            }
        }
        String normalized = trimmed.toUpperCase(Locale.ROOT).replace('-', '_');
        for (ExtKeyUsageType t : values()) {
            if (t.name().equals(normalized)) {
                return t;
            }
        }
        throw new IllegalArgumentException("Unsupported extKeyUsage: " + raw);
    }

    /**
     * 列表为空/null → 返回 {@code null}（由调用方决定是否填默认值）。
     */
    public static KeyPurposeId[] toBcArray(List<String> raws) {
        if (raws == null || raws.isEmpty()) {
            return null;
        }
        List<KeyPurposeId> ids = new ArrayList<>(raws.size());
        for (String raw : raws) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            ids.add(parse(raw).purpose());
        }
        return ids.isEmpty() ? null : ids.toArray(new KeyPurposeId[0]);
    }
}
