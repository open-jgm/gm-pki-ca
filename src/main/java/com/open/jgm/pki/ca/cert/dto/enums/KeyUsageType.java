package com.open.jgm.pki.ca.cert.dto.enums;

import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.List;
import java.util.Locale;

/**
 * RFC 5280 KeyUsage 位标志的字符串映射。
 * <p>
 * 解析大小写不敏感；未知值抛 {@link IllegalArgumentException}。
 */
public enum KeyUsageType {
    DIGITAL_SIGNATURE(KeyUsage.digitalSignature, "digitalSignature"),
    NON_REPUDIATION  (KeyUsage.nonRepudiation,   "nonRepudiation", "contentCommitment"),
    KEY_ENCIPHERMENT (KeyUsage.keyEncipherment,  "keyEncipherment"),
    DATA_ENCIPHERMENT(KeyUsage.dataEncipherment, "dataEncipherment"),
    KEY_AGREEMENT    (KeyUsage.keyAgreement,     "keyAgreement"),
    KEY_CERT_SIGN    (KeyUsage.keyCertSign,      "keyCertSign"),
    CRL_SIGN         (KeyUsage.cRLSign,          "cRLSign", "crlSign"),
    ENCIPHER_ONLY    (KeyUsage.encipherOnly,     "encipherOnly"),
    DECIPHER_ONLY    (KeyUsage.decipherOnly,     "decipherOnly");

    private final int bit;
    private final String[] aliases;

    KeyUsageType(int bit, String... aliases) {
        this.bit = bit;
        this.aliases = aliases;
    }

    /** @return BouncyCastle {@link KeyUsage} 位常量。 */
    public int bit() {
        return bit;
    }

    /** 大小写不敏感解析；未知值抛异常。 */
    public static KeyUsageType parse(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("KeyUsage 不能为 null");
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("KeyUsage 不能为空");
        }
        for (KeyUsageType t : values()) {
            if (t.name().equalsIgnoreCase(trimmed)) {
                return t;
            }
            for (String alias : t.aliases) {
                if (alias.equalsIgnoreCase(trimmed)) {
                    return t;
                }
            }
        }
        // 容错：尝试将 "key_cert_sign" 等下划线写法对齐 enum.name()
        String normalized = trimmed.toUpperCase(Locale.ROOT).replace('-', '_');
        for (KeyUsageType t : values()) {
            if (t.name().equals(normalized)) {
                return t;
            }
        }
        throw new IllegalArgumentException("Unsupported keyUsage: " + raw);
    }

    /**
     * 将字符串列表合并为 BC {@link KeyUsage}。
     * <p>
     * 列表为空/null → 返回 {@code null}（由调用方决定默认值）。
     */
    public static KeyUsage toBcKeyUsage(List<String> raws) {
        if (raws == null || raws.isEmpty()) {
            return null;
        }
        int mask = 0;
        for (String raw : raws) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            mask |= parse(raw).bit();
        }
        return mask == 0 ? null : new KeyUsage(mask);
    }
}
