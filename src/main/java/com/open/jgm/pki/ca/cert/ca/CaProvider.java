package com.open.jgm.pki.ca.cert.ca;

import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * T07：CA 提供者抽象。
 * <p>
 * 屏蔽「内置 CA」与「自建 CA」的差异，签发服务通过 {@code caId} 取 CA，未指定时取算法默认。
 * <p>
 * 实现：{@link InMemoryCaProvider}。
 */
public interface CaProvider {

    /** 取算法默认（内置）CA。ECC 默认为 prime256v1。 */
    CaIdentity getDefault(Algorithm algorithm);

    /** 取 ECC 指定曲线的内置 CA。 */
    CaIdentity getEccDefault(String curve);

    /** 按 caId 查找；未找到返回 empty。 */
    Optional<CaIdentity> findById(String caId);

    /** 列出所有 CA（内置 + 自建）。 */
    List<CaIdentity> list();

    /** 注册一个自建 CA；返回带 caId 的实例（持久化由实现决定）。 */
    CaIdentity register(CaIdentity ca);

    /** 删除自建 CA；内置 CA 不允许删除（抛 IllegalStateException）。 */
    void delete(String caId);

    /** 将 CA 私钥字节解析为 PrivateKey。 */
    PrivateKey toPrivateKey(CaIdentity ca);

    /** 将 CA 证书字节解析为 X509Certificate。 */
    X509Certificate toCertificate(CaIdentity ca);

    /** 取证书公钥。 */
    PublicKey toPublicKey(CaIdentity ca);
}
