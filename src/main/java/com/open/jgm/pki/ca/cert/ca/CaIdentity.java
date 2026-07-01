package com.open.jgm.pki.ca.cert.ca;

import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * T07：统一 CA 身份模型。
 * <p>
 * 字段含义：
 * <ul>
 *   <li>{@code caId}：唯一标识；内置 CA 形如 {@code builtin:SM2}/{@code builtin:RSA}/{@code builtin:ECC:prime256v1}；自建 CA 为 UUID。</li>
 *   <li>{@code name}：人类可读名称（Subject CN 或自定义）。</li>
 *   <li>{@code algorithm}：算法（SM2 / RSA / ECC）。</li>
 *   <li>{@code curve}：仅 ECC 有效（如 prime256v1），其它算法 null。</li>
 *   <li>{@code subCaCertDer}：子 CA 证书 DER 字节（持久化中以 base64 表示）。</li>
 *   <li>{@code subCaPrivateKeyPkcs8}：子 CA 私钥 PKCS#8 编码（持久化中以 base64 表示）。</li>
 *   <li>{@code rootCaCertDer}：根 CA 证书 DER（可空）。</li>
 *   <li>{@code builtin}：是否内置 CA（true 时不可删除）。</li>
 *   <li>{@code createdAt}：注册时间（毫秒）。</li>
 * </ul>
 * <p>
 * 私钥字节为敏感数据：仅在内存与持久化文件中存在，<b>不</b>暴露到 API 层。
 */
public final class CaIdentity {

    private final String caId;
    private final String name;
    private final Algorithm algorithm;
    private final String curve;
    private final byte[] subCaCertDer;
    private final byte[] subCaPrivateKeyPkcs8;
    private final byte[] rootCaCertDer;
    private final boolean builtin;
    private final long createdAt;

    public CaIdentity(String caId, String name, Algorithm algorithm, String curve,
                      byte[] subCaCertDer, byte[] subCaPrivateKeyPkcs8,
                      byte[] rootCaCertDer, boolean builtin, long createdAt) {
        this.caId = Objects.requireNonNull(caId, "caId");
        this.name = Objects.requireNonNull(name, "name");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.curve = curve;
        this.subCaCertDer = defensiveCopy(Objects.requireNonNull(subCaCertDer, "subCaCertDer"));
        this.subCaPrivateKeyPkcs8 = defensiveCopy(Objects.requireNonNull(subCaPrivateKeyPkcs8, "subCaPrivateKeyPkcs8"));
        this.rootCaCertDer = rootCaCertDer == null ? null : defensiveCopy(rootCaCertDer);
        this.builtin = builtin;
        this.createdAt = createdAt <= 0 ? Instant.now().toEpochMilli() : createdAt;
    }

    public String getCaId()            { return caId; }
    public String getName()            { return name; }
    public Algorithm getAlgorithm()    { return algorithm; }
    public String getCurve()           { return curve; }
    public byte[] getSubCaCertDer()    { return defensiveCopy(subCaCertDer); }
    public byte[] getSubCaPrivateKeyPkcs8() { return defensiveCopy(subCaPrivateKeyPkcs8); }
    public byte[] getRootCaCertDer()   { return rootCaCertDer == null ? null : defensiveCopy(rootCaCertDer); }
    public boolean isBuiltin()         { return builtin; }
    public long getCreatedAt()         { return createdAt; }

    private static byte[] defensiveCopy(byte[] src) {
        return Arrays.copyOf(src, src.length);
    }

    /** 内置 CA caId 生成规则：builtin:ALGO[:curve] */
    public static String builtinId(Algorithm algorithm, String curve) {
        if (curve != null && !curve.isBlank()) {
            return "builtin:" + algorithm.name() + ":" + curve;
        }
        return "builtin:" + algorithm.name();
    }
}
