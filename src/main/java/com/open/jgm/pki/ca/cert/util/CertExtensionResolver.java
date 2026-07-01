package com.open.jgm.pki.ca.cert.util;

import com.open.jgm.pki.ca.cert.dto.enums.ExtKeyUsageType;
import com.open.jgm.pki.ca.cert.dto.enums.KeyUsageType;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 将 {@code CertCreateDTO} 中的字符串扩展项解析为 BouncyCastle 的扩展对象。
 * <p>
 * 所有方法均为无副作用纯函数。
 * <ul>
 *   <li>{@link #resolveKeyUsage(List, KeyUsage)} — 用户未指定 → 返回默认。</li>
 *   <li>{@link #resolveExtendedKeyUsages(List, KeyPurposeId[])} — 同上。</li>
 *   <li>{@link #resolveSubjectAltNames(List)} — 支持 dns:/ip:/email:/rfc822:/uri:/dirName: 前缀，
 *       无前缀按 dns 处理；空/null → 返回空列表。</li>
 *   <li>{@link #resolveBasicConstraints(Boolean, Integer, boolean)} —
 *       basicConstraintsCA == null → 按 endEntityDefault 决定（true=非 CA）。</li>
 * </ul>
 */
public final class CertExtensionResolver {

    private CertExtensionResolver() {}

    /**
     * 解析 KeyUsage；未指定时返回 {@code fallback}。
     */
    public static KeyUsage resolveKeyUsage(List<String> raws, KeyUsage fallback) {
        KeyUsage parsed = KeyUsageType.toBcKeyUsage(raws);
        return parsed != null ? parsed : fallback;
    }

    /**
     * 解析 ExtendedKeyUsage；未指定时返回 {@code fallback}（可为 null 表示不输出该扩展）。
     */
    public static KeyPurposeId[] resolveExtendedKeyUsages(List<String> raws, KeyPurposeId[] fallback) {
        KeyPurposeId[] parsed = ExtKeyUsageType.toBcArray(raws);
        return parsed != null ? parsed : fallback;
    }

    /**
     * 解析 SAN 列表。
     * <p>
     * 每条字符串支持 "type:value" 形式，type ∈ {dns, ip, email, rfc822, uri, dirname}（大小写不敏感）；
     * 无冒号或未知 type 时按 DNS 处理。
     * <ul>
     *   <li>dns → {@link GeneralName#dNSName}</li>
     *   <li>ip → {@link GeneralName#iPAddress}</li>
     *   <li>email / rfc822 → {@link GeneralName#rfc822Name}</li>
     *   <li>uri → {@link GeneralName#uniformResourceIdentifier}</li>
     *   <li>dirname → {@link GeneralName#directoryName}（暂未实现，抛异常）</li>
     * </ul>
     */
    public static List<GeneralName> resolveSubjectAltNames(List<String> raws) {
        List<GeneralName> result = new ArrayList<>();
        if (raws == null || raws.isEmpty()) {
            return result;
        }
        for (String raw : raws) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String entry = raw.trim();
            String type;
            String value;
            int colon = entry.indexOf(':');
            if (colon > 0) {
                type = entry.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                value = entry.substring(colon + 1).trim();
            } else {
                type = "dns";
                value = entry;
            }
            if (value.isEmpty()) {
                continue;
            }
            switch (type) {
                case "dns":
                    result.add(new GeneralName(GeneralName.dNSName, new DERIA5String(value, true)));
                    break;
                case "ip":
                    result.add(new GeneralName(GeneralName.iPAddress, value));
                    break;
                case "email":
                case "rfc822":
                    result.add(new GeneralName(GeneralName.rfc822Name, new DERIA5String(value, true)));
                    break;
                case "uri":
                    result.add(new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(value, true)));
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported SAN type: " + type
                            + "（仅支持 dns/ip/email/rfc822/uri）");
            }
        }
        return result;
    }

    /**
     * 解析 BasicConstraints。
     *
     * @param ca               用户指定 CA 标志；null → 按 endEntityDefault
     * @param pathLen          路径长度限制（仅 CA 有效）；null → 无限制
     * @param endEntityDefault 默认是否为终端实体（true → 非 CA）
     */
    public static BasicConstraints resolveBasicConstraints(Boolean ca, Integer pathLen, boolean endEntityDefault) {
        boolean isCa;
        if (ca != null) {
            isCa = ca;
        } else {
            isCa = !endEntityDefault;
        }
        if (!isCa) {
            return new BasicConstraints(false);
        }
        return pathLen == null ? new BasicConstraints(true) : new BasicConstraints(pathLen);
    }
}
