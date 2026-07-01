package com.open.jgm.pki.ca.cert.service;

import cn.hutool.core.codec.Base64;
import com.open.jgm.pki.ca.cert.ca.CaIdentity;
import com.open.jgm.pki.ca.cert.ca.CaProvider;
import com.open.jgm.pki.ca.cert.config.CertConfig;
import com.open.jgm.pki.ca.cert.crypto.JksWriter;
import com.open.jgm.pki.ca.cert.crypto.RSAx509CertMaker;
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
import org.springframework.util.Base64Utils;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * RSA 证书服务，将 RsaCertController 中的业务私有方法迁移至此。
 */
@Service("rsaCertService")
@Slf4j
@RequiredArgsConstructor
public class RsaCertService implements ICertService {

    private final CertConfig certConfig;
    private final CertCacheManager cacheManager;
    private final CaProvider caProvider;

    @Override
    public String issueUserCert(CertIssueRequest request) {
        // RSA 默认 certUsage = SIGN（保持单证书行为）
        CertCreateDTO dto = CertDtoMapper.toDto(request, CertUsage.SIGN);
        validateAlgorithm(dto, Algorithm.RSA);
        validateUsageSupported(dto.getCertUsage());
        dto.setP12Password(certConfig.getP12Password());
        issueRsa(dto);
        return dto.getDn_cn();
    }

    private static void validateAlgorithm(CertCreateDTO dto, Algorithm expected) {
        Algorithm reqAlgo = dto.getAlgorithm();
        if (reqAlgo != null && reqAlgo != expected) {
            throw new CertException("请求 algorithm=" + reqAlgo + "，与当前服务 " + expected + " 不一致");
        }
    }

    private static void validateUsageSupported(CertUsage usage) {
        // T01: RSA 当前仅支持 SIGN；ENC/BOTH 留 T02 实现（双证书）
        if (usage != null && usage != CertUsage.SIGN) {
            throw new CertException("RSA 服务当前仅支持 certUsage=SIGN（双证书将在 T02 中实现），收到：" + usage);
        }
    }

    @Override
    public String issueUserCertByCSR(byte[] csrBytes) {
        return issueUserCertByCSRWithOverrides(csrBytes, null);
    }

    /** T06：RSA CSR 签发，允许通过 {@link CertCreateDTO} 追加扩展。overrides == null 时等价于旧行为。 */
    public String issueUserCertByCSRWithOverrides(byte[] csrBytes, CertCreateDTO overrides) {
        try {
            String universalName = SM2CertUtil.getUniversalName(
                    new org.bouncycastle.pkcs.PKCS10CertificationRequest(csrBytes).getSubject());
            issueRsaCSR(csrBytes, universalName, overrides);
            return universalName;
        } catch (CertException | BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("RSA CSR 签发失败", e);
            throw new CertException("RSA CSR 签发失败", e);
        }
    }

    @Override
    public CertIssuedResult getIssuedCert(String universalName) {
        if (!cacheManager.containsRsa(universalName)) {
            throw new BusinessException("RSA 证书不存在，请先签发");
        }
        return cacheManager.getRsa(universalName);
    }

    @Override
    public CaChainResult getCaChain() {
        try {
            byte[] rcaPem = SM2CertUtil.convertToPem(RSAx509CertMaker.rootCACert);
            byte[] ocaPem = SM2CertUtil.convertToPem(RSAx509CertMaker.subCACert);
            X509Certificate rca = SM2CertUtil.convertToX509Certificate(RSAx509CertMaker.rootCACert);
            X509Certificate oca = SM2CertUtil.convertToX509Certificate(RSAx509CertMaker.subCACert);
            byte[] p7b = SM2X509CertMaker.generateP7B(Arrays.asList(rca, oca));
            return new CaChainResult(
                    Base64.decode(RSAx509CertMaker.rootCACert), rcaPem,
                    Base64.decode(RSAx509CertMaker.subCACert),  ocaPem,
                    ZipDownloadHelper.mergeBytes(rcaPem, ocaPem), p7b);
        } catch (Exception e) {
            log.error("获取 RSA CA 链失败", e);
            throw new CertException("获取 RSA CA 链失败", e);
        }
    }

    @Override
    public CertDetailResult parseCert(String base64Cert) {
        return CertParseUtil.parse(base64Cert);
    }

    /** T10：caId 空 → 内置 RSA；否则查 Provider，校验算法匹配。 */
    private CaIdentity resolveCa(String caId) {
        if (caId == null || caId.isBlank()) {
            return caProvider.getDefault(Algorithm.RSA);
        }
        CaIdentity ca = caProvider.findById(caId)
                .orElseThrow(() -> new CertException("CA 不存在: " + caId));
        if (ca.getAlgorithm() != Algorithm.RSA) {
            throw new CertException("CA 算法不匹配，期望 RSA，实际 " + ca.getAlgorithm() + " (" + caId + ")");
        }
        return ca;
    }

    // ──────────────────────────────────────���─────────────────────
    // 核心业务方法
    // ────────────────────────────────────────────────────────────

    private void issueRsa(CertCreateDTO dto) {
        try {
            CaIdentity ca = resolveCa(dto.getCaId());
            String caCertB64 = Base64Utils.encodeToString(ca.getSubCaCertDer());
            CertDescInfo subCaInfo = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(caCertB64));
            KeyPair keyPair        = RSAx509CertMaker.generateRsaKeyPair(2048);
            RSAx509CertMaker maker = new RSAx509CertMaker();
            if (!ca.isBuiltin()) {
                maker.withIssuerKeys(caProvider.toPublicKey(ca), caProvider.toPrivateKey(ca));
            }

            X509CertificateHolder holder = maker.makeUserCertHolder(keyPair, dto, subCaInfo);
            X509Certificate userCert     = SM2CertUtil.convertToX509Certificate(holder.getEncoded());

            X509Certificate subCa = SM2CertUtil.convertToX509Certificate(caCertB64);
            userCert.verify(subCa.getPublicKey());
            if (!SM2X509CertMaker.isTruested(Base64Utils.encodeToString(userCert.getEncoded()), caCertB64)) {
                throw new CertException("RSA 用户证书验签失败");
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
            byte[] priPem  = RSAx509CertMaker.toRsaPriPem(keyPair.getPrivate());

            // T03：JKS 按需生成（RSA 默认支持），SM2 风险表明确不走 JKS
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

            cacheManager.putRsa(dto.getDn_cn(), result);
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("RSA 证书签发失败", e);
            throw new CertException("RSA 证书签发失败", e);
        }
    }

    private void issueRsaCSR(byte[] csrBytes, String universalName, CertCreateDTO overrides) {
        try {
            String caId = overrides != null ? overrides.getCaId() : null;
            CaIdentity ca = resolveCa(caId);
            String caCertB64 = Base64Utils.encodeToString(ca.getSubCaCertDer());
            CertDescInfo subCaInfo   = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(caCertB64));
            RSAx509CertMaker maker   = new RSAx509CertMaker();
            if (!ca.isBuiltin()) {
                maker.withIssuerKeys(caProvider.toPublicKey(ca), caProvider.toPrivateKey(ca));
            }
            X509CertificateHolder holder = maker.makeUserCertHolder(csrBytes, subCaInfo, overrides);
            X509Certificate userCert = SM2CertUtil.convertToX509Certificate(holder.getEncoded());

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

            cacheManager.putRsa(universalName, result);
        } catch (CertException | BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("RSA CSR 证书签发失败", e);
            throw new CertException("RSA CSR 证书签发失败", e);
        }
    }
}
