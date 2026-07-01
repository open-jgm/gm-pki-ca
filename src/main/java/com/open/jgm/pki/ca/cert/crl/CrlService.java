package com.open.jgm.pki.ca.cert.crl;

import cn.hutool.core.util.HexUtil;
import com.open.jgm.pki.ca.cert.ca.CaIdentity;
import com.open.jgm.pki.ca.cert.ca.CaProvider;
import com.open.jgm.pki.ca.cert.crl.dto.CrlGenerateRequest;
import com.open.jgm.pki.ca.cert.crl.dto.CrlInfo;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.exception.CertException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * T26-T27：CRL 生成与解析。
 * <p>
 * 生成：根据指定 caId 取 CA 私钥；按算法选择 sigAlg（SM2→SM3withSM2、RSA→SHA256withRSA、ECC→SHA256withECDSA）。
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CrlService {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private final CaProvider caProvider;

    // ──────────────────────────────────────────────────────────
    // T26：生成
    // ──────────────────────────────────────────────────────────

    public byte[] generate(CrlGenerateRequest req) {
        if (req == null || req.getRevoked() == null || req.getRevoked().isEmpty()) {
            throw new CertException("revoked 不能为空");
        }
        CaIdentity ca = resolveCa(req.getCaId());

        try {
            var caCert = caProvider.toCertificate(ca);
            X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

            Date thisUpdate = new Date();
            int days = req.getValidDays() == null || req.getValidDays() <= 0 ? 30 : req.getValidDays();
            Date nextUpdate = new Date(thisUpdate.getTime() + (long) days * 24 * 3600 * 1000);

            X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, thisUpdate);
            builder.setNextUpdate(nextUpdate);

            for (CrlGenerateRequest.RevokedEntry e : req.getRevoked()) {
                BigInteger serial = parseSerial(e.getSerialNumberHex());
                Date rDate = parseDate(e.getRevocationDate());
                int reason = e.getReason() == null ? CRLReason.unspecified : e.getReason();
                builder.addCRLEntry(serial, rDate, reason);
            }

            // AKI 扩展
            try {
                JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
                builder.addExtension(Extension.authorityKeyIdentifier, false,
                        extUtils.createAuthorityKeyIdentifier(caCert));
            } catch (Exception ex) {
                log.warn("CRL AKI 扩展生成失败（继续）: {}", ex.getMessage());
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(ca))
                    .setProvider(BC).build(caProvider.toPrivateKey(ca));
            X509CRLHolder holder = builder.build(signer);
            return holder.getEncoded();
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("CRL 生成失败", e);
            throw new CertException("CRL 生成失败: " + e.getMessage(), e);
        }
    }

    // ──────────────────────────────────────────────────────────
    // T27：解析
    // ──────────────────────────────────────────────────────────

    public CrlInfo parse(byte[] der) {
        if (der == null || der.length == 0) {
            throw new CertException("CRL 字节不能为空");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
            X509CRL crl = (X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(der));

            List<CrlInfo.RevokedView> revoked = new ArrayList<>();
            if (crl.getRevokedCertificates() != null) {
                for (X509CRLEntry e : crl.getRevokedCertificates()) {
                    revoked.add(CrlInfo.RevokedView.builder()
                            .serialNumberHex(HexUtil.encodeHexStr(e.getSerialNumber().toByteArray()))
                            .revocationDate(formatInstant(e.getRevocationDate().toInstant()))
                            .reason(e.getRevocationReason() == null ? null : e.getRevocationReason().ordinal())
                            .build());
                }
            }

            return CrlInfo.builder()
                    .version(crl.getVersion())
                    .issuer(crl.getIssuerX500Principal().getName())
                    .signatureAlgorithmOid(crl.getSigAlgOID())
                    .thisUpdate(formatInstant(crl.getThisUpdate().toInstant()))
                    .nextUpdate(crl.getNextUpdate() == null ? null : formatInstant(crl.getNextUpdate().toInstant()))
                    .revokedCount(revoked.size())
                    .revoked(revoked)
                    .build();
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("CRL 解析失败: " + e.getMessage(), e);
        }
    }

    // ──────────────────────────────────────────────────────────

    private CaIdentity resolveCa(String caId) {
        if (caId == null || caId.isBlank()) {
            return caProvider.getDefault(Algorithm.SM2);
        }
        return caProvider.findById(caId)
                .orElseThrow(() -> new CertException("CA 不存在: " + caId));
    }

    private static String signatureAlgorithm(CaIdentity ca) {
        return switch (ca.getAlgorithm()) {
            case SM2 -> "SM3withSM2";
            case RSA -> "SHA256withRSA";
            case ECC -> "SHA256withECDSA";
        };
    }

    private static BigInteger parseSerial(String hex) {
        if (hex == null || hex.isBlank()) {
            throw new CertException("serialNumberHex 不能为空");
        }
        String s = hex.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        try {
            return new BigInteger(s, 16);
        } catch (NumberFormatException e) {
            throw new CertException("serialNumberHex 不是合法 hex: " + hex);
        }
    }

    private static Date parseDate(String iso) {
        if (iso == null || iso.isBlank()) return new Date();
        try {
            return Date.from(OffsetDateTime.parse(iso).toInstant());
        } catch (Exception e) {
            try {
                return Date.from(Instant.parse(iso));
            } catch (Exception ex) {
                throw new CertException("revocationDate 不是合法 ISO-8601: " + iso);
            }
        }
    }

    private static String formatInstant(Instant t) {
        return DateTimeFormatter.ISO_INSTANT.format(t.atOffset(ZoneOffset.UTC).toInstant());
    }
}
