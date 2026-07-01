package com.open.jgm.pki.ca.cert.dto.enums;

/**
 * 证书用途枚举：
 * <ul>
 *   <li>{@link #SIGN}：仅签名证书</li>
 *   <li>{@link #ENC}：仅加密证书</li>
 *   <li>{@link #BOTH}：签名 + 加密双证书（国密典型场景）</li>
 * </ul>
 * <p>
 * 默认行为（在请求未显式指定时）：
 * <ul>
 *   <li>SM2 → {@link #BOTH}（保持原有双证书行为）</li>
 *   <li>RSA / ECC → {@link #SIGN}（保持单证书行为）</li>
 * </ul>
 */
public enum CertUsage {

    SIGN,
    ENC,
    BOTH;

    public static CertUsage parseOrNull(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return CertUsage.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported certUsage: " + raw);
        }
    }

    /** 是否需要生成签名证书部分。 */
    public boolean needsSign() {
        return this == SIGN || this == BOTH;
    }

    /** 是否需要生成加密证书部分。 */
    public boolean needsEnc() {
        return this == ENC || this == BOTH;
    }
}
