package com.open.jgm.pki.ca.cert.inspect;

import cn.hutool.core.util.HexUtil;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.inspect.dto.ChainInspectRequest;
import com.open.jgm.pki.ca.cert.inspect.dto.ChainInspectResult;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * T25：证书链信任路径验证。
 * <p>
 * 算法：对链 i 的 issuer 必须等于链 i+1 的 subject；用 i+1 的公钥验签 i 的签名；
 * 末段如果不是自签且没有匹配 trustAnchor，则视为信任链断裂；
 * 有 trustAnchors 时寻找其中 subject 等于链末段 issuer 的锚，用其公钥校验末段。
 */
@Service
public class ChainInspectService {

    public ChainInspectResult inspect(ChainInspectRequest req) {
        if (req == null || req.getChain() == null || req.getChain().isEmpty()) {
            throw new CertException("chain 不能为空");
        }
        List<X509Certificate> chain = req.getChain().stream().map(PemKeyReader::readCert).toList();
        List<X509Certificate> anchors = req.getTrustAnchors() == null ? List.of()
                : req.getTrustAnchors().stream().map(PemKeyReader::readCert).toList();

        List<ChainInspectResult.Node> nodes = new ArrayList<>(chain.size());
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            nodes.add(ChainInspectResult.Node.builder()
                    .index(i)
                    .subject(c.getSubjectX500Principal().getName())
                    .issuer(c.getIssuerX500Principal().getName())
                    .serialNumberHex(HexUtil.encodeHexStr(c.getSerialNumber().toByteArray()))
                    .notBefore(formatInstant(c.getNotBefore().toInstant()))
                    .notAfter(formatInstant(c.getNotAfter().toInstant()))
                    .signatureVerified(null)
                    .build());
        }

        // 链内相邻校验：i 的 issuer == i+1 的 subject 且 i+1 公钥能验签 i
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate ee     = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            if (!ee.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                nodes.get(i).setSignatureVerified(false);
                return failed(nodes, i, "链节点 " + i + " 的 issuer 与节点 " + (i + 1) + " 的 subject 不匹配");
            }
            try {
                ee.verify(issuer.getPublicKey());
                nodes.get(i).setSignatureVerified(true);
            } catch (Exception e) {
                nodes.get(i).setSignatureVerified(false);
                return failed(nodes, i, "节点 " + i + " 签名验证失败: " + e.getMessage());
            }
        }

        // 链末段：自签或匹配 trustAnchor
        X509Certificate tail = chain.get(chain.size() - 1);
        if (tail.getIssuerX500Principal().equals(tail.getSubjectX500Principal())) {
            // 自签根：用自身公钥验签
            try {
                tail.verify(tail.getPublicKey());
                nodes.get(chain.size() - 1).setSignatureVerified(true);
            } catch (Exception e) {
                nodes.get(chain.size() - 1).setSignatureVerified(false);
                return failed(nodes, chain.size() - 1, "链末段自签验证失败: " + e.getMessage());
            }
        } else if (!anchors.isEmpty()) {
            X509Certificate anchor = anchors.stream()
                    .filter(a -> a.getSubjectX500Principal().equals(tail.getIssuerX500Principal()))
                    .findFirst()
                    .orElse(null);
            if (anchor == null) {
                nodes.get(chain.size() - 1).setSignatureVerified(false);
                return failed(nodes, chain.size() - 1, "trustAnchors 中没有 subject 匹配链末段 issuer 的证书");
            }
            try {
                tail.verify(anchor.getPublicKey());
                nodes.get(chain.size() - 1).setSignatureVerified(true);
            } catch (Exception e) {
                nodes.get(chain.size() - 1).setSignatureVerified(false);
                return failed(nodes, chain.size() - 1, "链末段对锚验签失败: " + e.getMessage());
            }
        } else {
            // 既非自签，又未提供 anchor — 标记成功（仅相邻有效）但 trusted=false
            nodes.get(chain.size() - 1).setSignatureVerified(null);
            return ChainInspectResult.builder()
                    .trusted(false)
                    .brokenAtIndex(null)
                    .reason("链非自签且未提供 trustAnchors，无法判定根信任")
                    .nodes(nodes).build();
        }

        return ChainInspectResult.builder()
                .trusted(true)
                .brokenAtIndex(null)
                .reason(null)
                .nodes(nodes).build();
    }

    private static ChainInspectResult failed(List<ChainInspectResult.Node> nodes, int idx, String reason) {
        return ChainInspectResult.builder()
                .trusted(false).brokenAtIndex(idx).reason(reason).nodes(nodes).build();
    }

    private static String formatInstant(Instant t) {
        return DateTimeFormatter.ISO_INSTANT.format(t.atOffset(ZoneOffset.UTC).toInstant());
    }
}
