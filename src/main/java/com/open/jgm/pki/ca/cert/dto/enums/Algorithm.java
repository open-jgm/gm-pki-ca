package com.open.jgm.pki.ca.cert.dto.enums;

import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;

/**
 * 证书算法枚举：覆盖国密 SM2、国际 RSA、ECC（椭圆曲线）。
 * <p>
 * T01 起作为 {@link CertIssueRequest#getAlgorithm()} 的合法取值，
 * 用于在统一入口下区分签发算法。各算法 Service 可以校验请求与自身一致。
 */
public enum Algorithm {

    SM2,
    RSA,
    ECC;

    /**
     * 大小写不敏感的安全解析；返回 {@code null} 表示未指定。
     */
    public static Algorithm parseOrNull(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Algorithm.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported algorithm: " + raw);
        }
    }
}
