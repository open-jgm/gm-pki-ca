package com.open.jgm.pki.ca.cert.service;

import cn.hutool.core.codec.Base64;
import com.open.jgm.pki.ca.cert.ca.CaIdentity;
import com.open.jgm.pki.ca.cert.ca.CaProvider;
import com.open.jgm.pki.ca.cert.config.CertConfig;
import com.open.jgm.pki.ca.cert.crypto.ECCx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.JksWriter;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertDetailResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.util.CertDtoMapper;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import com.open.jgm.pki.ca.cert.util.ZipDownloadHelper;
import com.open.jgm.pki.ca.cert.crypto.*;
import com.open.jgm.pki.ca.cert.dto.internal.*;
import com.open.jgm.pki.ca.framework.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * ECC 证书服务，支持 prime256v1 / brainpoolP256r1 / FRP256v1 三条曲线。
 * <p>
 * 额外提供带曲线参数的方法，由 EccCertController 直接调用。
 */
@Service("eccCertService")
@Slf4j
@RequiredArgsConstructor
public class EccCertService implements ICertService {

    private final CertConfig certConfig;
    private final CertCacheManager cacheManager;
    private final CaProvider caProvider;

    // ────────────────────────────────────────────────────────────
    // ICertService 实现（默认曲线 prime256v1）
    // ────────────────────────────────────────────────────────────

    @Override
    public String issueUserCert(CertIssueRequest request) {
        return issueUserCertForCurve(ECCx509CertMaker.CurveType.PRIME256V1, request);
    }

    @Override
    public String issueUserCertByCSR(byte[] csrBytes) {
        return issueUserCertByCSRForCurve(ECCx509CertMaker.CurveType.PRIME256V1, csrBytes);
    }

    @Override
    public CertIssuedResult getIssuedCert(String universalName) {
        return getIssuedCertForCurve(ECCx509CertMaker.CurveType.PRIME256V1, universalName);
    }

    @Override
    public CaChainResult getCaChain() {
        return getCaChainForCurve(ECCx509CertMaker.CurveType.PRIME256V1);
    }

    @Override
    public CertDetailResult parseCert(String base64Cert) {
        return CertParseUtil.parse(base64Cert);
    }

    /** T10：caId 空 → 内置 ECC 对应曲线；否则查 Provider，校验算法/曲线匹配。 */
    private CaIdentity resolveCa(String caId, ECCx509CertMaker.CurveType curveType) {
        if (caId == null || caId.isBlank()) {
            return caProvider.getEccDefault(curveType.getUrlKey());
        }
        CaIdentity ca = caProvider.findById(caId)
                .orElseThrow(() -> new CertException("CA 不存在: " + caId));
        if (ca.getAlgorithm() != Algorithm.ECC) {
            throw new CertException("CA 算法不匹配，期望 ECC，实际 " + ca.getAlgorithm() + " (" + caId + ")");
        }
        if (ca.getCurve() != null && !ca.getCurve().equalsIgnoreCase(curveType.getUrlKey())) {
            throw new CertException("CA 曲线不匹配，期望 " + curveType.getUrlKey()
                    + "，实际 " + ca.getCurve() + " (" + caId + ")");
        }
        return ca;
    }

    // ────────────────────────────────────────────────────────────
    // 带曲线参数的扩展方法（供 EccCertController 调用）
    // ────────────────────────────────────────────────────────────

    public String issueUserCertForCurve(ECCx509CertMaker.CurveType curveType, CertIssueRequest request) {
        // ECC 默认 certUsage = SIGN（保持单证书行为）
        CertCreateDTO dto = CertDtoMapper.toDto(request, CertUsage.SIGN);
        validateAlgorithm(dto, Algorithm.ECC);
        validateUsageSupported(dto.getCertUsage());
        dto.setP12Password(certConfig.getP12Password());
        issueEcc(curveType, dto);
        return dto.getDn_cn();
    }

    private static void validateAlgorithm(CertCreateDTO dto, Algorithm expected) {
        Algorithm reqAlgo = dto.getAlgorithm();
        if (reqAlgo != null && reqAlgo != expected) {
            throw new CertException("请求 algorithm=" + reqAlgo + "，与当前服务 " + expected + " 不一致");
        }
    }

    private static void validateUsageSupported(CertUsage usage) {
        // T01: ECC 当前仅支持 SIGN；ENC/BOTH 留 T02 实现
        if (usage != null && usage != CertUsage.SIGN) {
            throw new CertException("ECC 服务当前仅支持 certUsage=SIGN（双证书将在 T02 中实现），收到：" + usage);
        }
    }

    public String issueUserCertByCSRForCurve(ECCx509CertMaker.CurveType curveType, byte[] csrBytes) {
        return issueUserCertByCSRForCurveWithOverrides(curveType, csrBytes, null);
    }

    /** T06：ECC CSR 签发，允许通过 {@link CertCreateDTO} 追加扩展。overrides == null 时等价于旧行为。 */
    public String issueUserCertByCSRForCurveWithOverrides(ECCx509CertMaker.CurveType curveType,
                                                          byte[] csrBytes,
                                                          CertCreateDTO overrides) {
        try {
            String universalName = SM2CertUtil.getUniversalName(
                    new org.bouncycastle.pkcs.PKCS10CertificationRequest(csrBytes).getSubject());
            issueEccCSR(curveType, csrBytes, universalName, overrides);
            return universalName;
        } catch (CertException | BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("ECC CSR 签发失败 [{}]", curveType, e);
            throw new CertException("ECC CSR 签发失败", e);
        }
    }

    public CertIssuedResult getIssuedCertForCurve(ECCx509CertMaker.CurveType curveType, String universalName) {
        if (!cacheManager.containsEcc(curveType.getUrlKey(), universalName)) {
            throw new BusinessException("ECC 证书不存在，请先签发");
        }
        return cacheManager.getEcc(curveType.getUrlKey(), universalName);
    }

    public CaChainResult getCaChainForCurve(ECCx509CertMaker.CurveType curveType) {
        try {
            ECCx509CertMaker.CaBundle bundle = ECCx509CertMaker.CA_BUNDLES.get(curveType);
            byte[] rcaPem = SM2CertUtil.convertToPem(bundle.rootCACert);
            byte[] ocaPem = SM2CertUtil.convertToPem(bundle.subCACert);
            X509Certificate rca = SM2CertUtil.convertToX509Certificate(bundle.rootCACert);
            X509Certificate oca = SM2CertUtil.convertToX509Certificate(bundle.subCACert);
            byte[] p7b = SM2X509CertMaker.generateP7B(Arrays.asList(rca, oca));
            return new CaChainResult(
                    Base64.decode(bundle.rootCACert), rcaPem,
                    Base64.decode(bundle.subCACert),  ocaPem,
                    ZipDownloadHelper.mergeBytes(rcaPem, ocaPem), p7b);
        } catch (Exception e) {
            log.error("获取 ECC CA 链失败 [{}]", curveType, e);
            throw new CertException("获取 ECC CA 链失败", e);
        }
    }

    // ────────────────────────────────────────────────────────────
    // 核心业务方法
    // ────────────────────────────────────────────────────────────

    private void issueEcc(ECCx509CertMaker.CurveType curveType, CertCreateDTO dto) {
        try {
            CaIdentity ca = resolveCa(dto.getCaId(), curveType);
            String caCertB64 = Base64.encode(ca.getSubCaCertDer());
            CertDescInfo subCaInfo           = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(caCertB64));
            KeyPair keyPair                  = ECCx509CertMaker.generateEccKeyPair(curveType);
            ECCx509CertMaker maker           = new ECCx509CertMaker(curveType);
            if (!ca.isBuiltin()) {
                maker.withIssuerKeys(caProvider.toPublicKey(ca), caProvider.toPrivateKey(ca));
            }

            X509CertificateHolder holder = maker.makeUserCertHolder(keyPair, dto, subCaInfo);
            X509Certificate userCert     = SM2CertUtil.convertToX509Certificate(holder.getEncoded());

            X509Certificate subCa = SM2CertUtil.convertToX509Certificate(caCertB64);
            userCert.verify(subCa.getPublicKey());
            if (!SM2X509CertMaker.isTruested(Base64.encode(userCert.getEncoded()), caCertB64)) {
                throw new CertException("ECC 用户证书验签失败");
            }

            char[] pwd = certConfig.getP12Password().toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, pwd);
            ks.setKeyEntry("alias", keyPair.getPrivate(), pwd, new java.security.cert.Certificate[]{userCert});
            byte[] p12;
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                ks.store(baos, pwd);
                p12 = baos.toByteArray();
            }

            byte[] certPem = SM2CertUtil.convertToPem(userCert);
            byte[] priPem  = ECCx509CertMaker.toEccPriPem(keyPair.getPrivate());

            byte[] empty = new byte[0];
            byte[] jks = empty;
            if (dto.getOutputFormats() != null && dto.getOutputFormats().contains(OutputFormat.JKS)) {
                jks = JksWriter.write(
                        keyPair.getPrivate(), userCert, certConfig.getP12Password());
            }

            CertIssuedResult result = CertIssuedResult.builder()
                    .sigP12Byte(p12).sigCertByte(userCert.getEncoded()).sigCertPemByte(certPem)
                    .sigPriPemByte(priPem).sigKeyPemByte(priPem)
                    .encP12Byte(empty).encCertByte(empty).encCertPemByte(empty)
                    .encPriPemByte(empty).encKeyPemByte(empty)
                    .encKeyEnvelopeByte(empty).bothP12Byte(p12).pwdTxt(empty)
                    .sigJksByte(jks).encJksByte(empty).bothJksByte(jks)
                    .requestedFormats(dto.getOutputFormats())
                    .build();

            cacheManager.putEcc(curveType.getUrlKey(), dto.getDn_cn(), result);
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("ECC 证书签发失败 [{}]", curveType, e);
            throw new CertException("ECC 证书签发失败", e);
        }
    }

    private void issueEccCSR(ECCx509CertMaker.CurveType curveType, byte[] csrBytes, String universalName,
                             CertCreateDTO overrides) {
        try {
            String caId = overrides != null ? overrides.getCaId() : null;
            CaIdentity ca = resolveCa(caId, curveType);
            String caCertB64 = Base64.encode(ca.getSubCaCertDer());
            CertDescInfo subCaInfo           = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(caCertB64));
            ECCx509CertMaker maker           = new ECCx509CertMaker(curveType);
            if (!ca.isBuiltin()) {
                maker.withIssuerKeys(caProvider.toPublicKey(ca), caProvider.toPrivateKey(ca));
            }
            X509CertificateHolder holder     = maker.makeUserCertHolder(csrBytes, subCaInfo, overrides);
            X509Certificate userCert         = SM2CertUtil.convertToX509Certificate(holder.getEncoded());

            X509Certificate subCa = SM2CertUtil.convertToX509Certificate(caCertB64);
            userCert.verify(subCa.getPublicKey());

            byte[] certPem = SM2CertUtil.convertToPem(userCert);

            byte[] empty = new byte[0];
            CertIssuedResult result = CertIssuedResult.builder()
                    .sigCertByte(userCert.getEncoded()).sigCertPemByte(certPem)
                    .sigP12Byte(empty).sigPriPemByte(empty).sigKeyPemByte(empty)
                    .encP12Byte(empty).encCertByte(empty).encCertPemByte(empty)
                    .encPriPemByte(empty).encKeyPemByte(empty)
                    .encKeyEnvelopeByte(empty).bothP12Byte(empty).pwdTxt(empty)
                    .sigJksByte(empty).encJksByte(empty).bothJksByte(empty)
                    .build();

            cacheManager.putEcc(curveType.getUrlKey(), universalName, result);
        } catch (CertException | BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("ECC CSR 证书签发失败 [{}]", curveType, e);
            throw new CertException("ECC CSR 证书签发失败", e);
        }
    }
}
