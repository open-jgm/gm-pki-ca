package com.open.jgm.pki.ca.cert.service;

import cn.hutool.core.codec.Base64;
import com.open.jgm.pki.ca.cert.ca.CaIdentity;
import com.open.jgm.pki.ca.cert.ca.CaProvider;
import com.open.jgm.pki.ca.cert.config.CertConfig;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertDetailResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.util.CertDtoMapper;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import com.open.jgm.pki.ca.cert.util.ZipDownloadHelper;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.framework.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * SM2 证书服务，将原 CertController 中所有 private static 业务方法迁移至此。
 */
@Service("sm2CertService")
@Slf4j
@RequiredArgsConstructor
public class Sm2CertService implements ICertService {

    private final CertConfig certConfig;
    private final CertCacheManager cacheManager;
    private final CaProvider caProvider;

    // ────────────────────────────────────────────────────────────
    // ICertService 实现
    // ────────────────────────────────────────────────────────────

    @Override
    public String issueUserCert(CertIssueRequest request) {
        // SM2 默认 certUsage = BOTH（保持原有双证书行为）
        CertCreateDTO dto = CertDtoMapper.toDto(request, CertUsage.BOTH);
        validateAlgorithm(dto, Algorithm.SM2);
        dto.setP12Password(certConfig.getP12Password());
        createIssue(dto);
        return dto.getDn_cn();
    }

    private static void validateAlgorithm(CertCreateDTO dto, Algorithm expected) {
        Algorithm reqAlgo = dto.getAlgorithm();
        if (reqAlgo != null && reqAlgo != expected) {
            throw new CertException("请求 algorithm=" + reqAlgo + "，与当前服务 " + expected + " 不一致");
        }
    }

    @Override
    public String issueUserCertByCSR(byte[] csrBytes) {
        return issueUserCertByCSRWithOverrides(csrBytes, null);
    }

    /** T06：CSR 签发，允许通过 {@link CertCreateDTO} 追加扩展。overrides == null 时等价于旧行为。 */
    public String issueUserCertByCSRWithOverrides(byte[] csrBytes, CertCreateDTO overrides) {
        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
            String universalName = SM2CertUtil.getUniversalName(csr.getSubject());
            createIssueCSR(csrBytes, universalName, overrides);
            return universalName;
        } catch (CertException | BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("SM2 CSR 签发失败", e);
            throw new CertException("SM2 CSR 签发失败", e);
        }
    }

    @Override
    public CertIssuedResult getIssuedCert(String universalName) {
        if (!cacheManager.containsSm2(universalName)) {
            throw new BusinessException("SM2 证书不存在，请先签发");
        }
        return cacheManager.getSm2(universalName);
    }

    @Override
    public CaChainResult getCaChain() {
        try {
            byte[] rcaPem = SM2CertUtil.convertToPem(SM2X509CertMaker.rootCACert);
            byte[] ocaPem = SM2CertUtil.convertToPem(SM2X509CertMaker.subCACert);
            X509Certificate rca = SM2CertUtil.convertToX509Certificate(SM2X509CertMaker.rootCACert);
            X509Certificate oca = SM2CertUtil.convertToX509Certificate(SM2X509CertMaker.subCACert);
            byte[] p7b = SM2X509CertMaker.generateP7B(Arrays.asList(rca, oca));
            return new CaChainResult(
                    Base64.decode(SM2X509CertMaker.rootCACert), rcaPem,
                    Base64.decode(SM2X509CertMaker.subCACert),  ocaPem,
                    ZipDownloadHelper.mergeBytes(rcaPem, ocaPem), p7b);
        } catch (Exception e) {
            log.error("获取 SM2 CA 链失败", e);
            throw new CertException("获取 SM2 CA 链失败", e);
        }
    }

    @Override
    public CertDetailResult parseCert(String base64Cert) {
        return CertParseUtil.parse(base64Cert);
    }

    // ────────────────────────────────────────────────────────────
    // 核心业务方法（从 CertController private static 迁移）
    // ────────────────────────────────────────────────────────────

    private void createIssue(CertCreateDTO dto) {
        // T01: 按 certUsage 决定生成签名/加密/双证书；默认 BOTH（mapper 已补默认）
        CertUsage usage = dto.getCertUsage() != null ? dto.getCertUsage() : CertUsage.BOTH;

        // T10: 解析 CA（caId 空 → 内置 SM2）
        CaIdentity ca = resolveCa(dto.getCaId());

        P12Bundle sig = null;
        P12Bundle enc = null;
        KeyPair encKeyPair = null;

        if (usage.needsSign()) {
            KeyPair sigKeyPair = SM2X509CertMaker.softSm2KeyPair();
            sig = buildP12Bundle(sigKeyPair, dto, ca);
        }
        if (usage.needsEnc()) {
            encKeyPair = SM2X509CertMaker.softSm2KeyPair();
            enc = buildP12Bundle(encKeyPair, dto, ca);
        }

        // 数字信封仅在 BOTH（既有签名证书又有加密私钥）时生成
        byte[] encKeyEnvelope = new byte[0];
        if (usage == CertUsage.BOTH && sig != null && encKeyPair != null) {
            try {
                X509Certificate sigCert = SM2CertUtil.convertToX509Certificate(sig.certDer);
                encKeyEnvelope = SM2X509CertMaker.wrapPrivateKeyAsEnvelope(
                        encKeyPair.getPrivate().getEncoded(), sigCert);
            } catch (Exception e) {
                log.error("生成加密私钥数字信封失败，将以空信封继续（需排查）", e);
            }
        }

        byte[] empty = new byte[0];
        byte[] sigP12     = sig != null ? sig.p12     : empty;
        byte[] sigCertDer = sig != null ? sig.certDer : empty;
        byte[] sigCertPem = sig != null ? sig.certPem : empty;
        byte[] sigPriPem  = sig != null ? sig.priPem  : empty;
        byte[] sigPriKey  = sig != null ? sig.priKey  : empty;
        byte[] encP12     = enc != null ? enc.p12     : empty;
        byte[] encCertDer = enc != null ? enc.certDer : empty;
        byte[] encCertPem = enc != null ? enc.certPem : empty;
        byte[] encPriPem  = enc != null ? enc.priPem  : empty;
        byte[] encPriKey  = enc != null ? enc.priKey  : empty;

        // bothP12Byte：按 usage 选择合并/单边/空
        byte[] bothP12;
        if (usage == CertUsage.BOTH) {
            bothP12 = ZipDownloadHelper.mergeBytes(sigP12, encP12);
        } else if (usage == CertUsage.SIGN) {
            bothP12 = sigP12;
        } else { // ENC
            bothP12 = encP12;
        }

        // T03: 透传请求格式集合，供 ZipDownloadHelper 过滤；SM2 不支持 JKS（见风险表）
        CertIssuedResult result = CertIssuedResult.builder()
                .sigP12Byte(sigP12).sigCertByte(sigCertDer).sigCertPemByte(sigCertPem)
                .sigPriPemByte(sigPriPem).sigKeyPemByte(sigPriKey)
                .encP12Byte(encP12).encCertByte(encCertDer).encCertPemByte(encCertPem)
                .encPriPemByte(encPriPem).encKeyPemByte(encPriKey)
                .bothP12Byte(bothP12)
                .encKeyEnvelopeByte(encKeyEnvelope).pwdTxt(empty)
                .sigJksByte(empty).encJksByte(empty).bothJksByte(empty)
                .requestedFormats(dto.getOutputFormats())
                .build();

        cacheManager.putSm2(dto.getDn_cn(), result);
    }

    private void createIssueCSR(byte[] csrBytes, String universalName, CertCreateDTO overrides) throws IOException {
        // T10: 解析 CA（CSR 路径下从 overrides 取 caId）
        String caId = overrides != null ? overrides.getCaId() : null;
        CaIdentity ca = resolveCa(caId);
        byte[] caCertDer = ca.getSubCaCertDer();
        String caCertB64 = java.util.Base64.getEncoder().encodeToString(caCertDer);

        CertDescInfo legacySubCaInfo = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(caCertB64));
        SM2X509CertMaker maker = new SM2X509CertMaker();
        if (!ca.isBuiltin()) {
            maker.withIssuerKeys(caProvider.toPublicKey(ca), caProvider.toPrivateKey(ca));
        }
        X509CertificateHolder holder = maker.makeUserCertHolder(csrBytes, legacySubCaInfo, overrides);
        X509Certificate userCert = SM2CertUtil.convertToX509Certificate(holder.getEncoded());

        try {
            X509Certificate subCa = SM2CertUtil.convertToX509Certificate(caCertB64);
            userCert.verify(subCa.getPublicKey());
            String b64 = java.util.Base64.getEncoder().encodeToString(userCert.getEncoded());
            if (!SM2X509CertMaker.isTruested(b64, caCertB64)) {
                throw new CertException("SM2 CSR 证书验签失败");
            }
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("SM2 CSR 证书验证失败", e);
            throw new CertException("SM2 CSR 证书验证失败", e);
        }

        byte[] certPem;
        try {
            certPem = SM2CertUtil.convertToPem(userCert);
        } catch (Exception e) {
            throw new CertException("SM2 CSR 证书转 PEM 失败", e);
        }

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

        // 国密双证书：CSR 路径仍需为用户生成服务端加密证书
        CertCreateDTO encDto = new CertCreateDTO();
        encDto.setDn_cn(universalName);
        encDto.setDn_c(SM2CertUtil.getDnItemValue(csr.getSubject().toString(),"C"));
        encDto.setDn_o(SM2CertUtil.getDnItemValue(csr.getSubject().toString(),"O"));
        encDto.setDn_ou(SM2CertUtil.getDnItemValue(csr.getSubject().toString(),"OU"));
        encDto.setCertValidMonth(certConfig.getCsrEncCertValidMonths());
        encDto.setCaId(caId);
        KeyPair encKeyPair = SM2X509CertMaker.softSm2KeyPair();
        P12Bundle enc = buildP12Bundle(encKeyPair, encDto, ca);

        byte[] encKeyEnvelope = new byte[0];
        try {
            encKeyEnvelope = SM2X509CertMaker.wrapPrivateKeyAsEnvelope(
                    encKeyPair.getPrivate().getEncoded(), userCert);
        } catch (Exception e) {
            log.error("CSR 路径：生成加密私钥数字信封失败，将以空信封继续（需排查）", e);
        }

        CertIssuedResult result;
        try {
            byte[] empty = new byte[0];
            result = CertIssuedResult.builder()
                    .sigCertByte(userCert.getEncoded()).sigCertPemByte(certPem)
                    .sigP12Byte(empty).sigPriPemByte(empty).sigKeyPemByte(empty)
                    .encP12Byte(enc.p12).encCertByte(enc.certDer).encCertPemByte(enc.certPem)
                    .encPriPemByte(enc.priPem).encKeyPemByte(enc.priKey)
                    .bothP12Byte(enc.p12).encKeyEnvelopeByte(encKeyEnvelope).pwdTxt(empty)
                    .sigJksByte(empty).encJksByte(empty).bothJksByte(empty)
                    .build();
        } catch (Exception e) {
            throw new CertException("SM2 CSR 证书结果构建失败", e);
        }

        cacheManager.putSm2(universalName, result);
    }

    private P12Bundle buildP12Bundle(KeyPair keyPair, CertCreateDTO dto, CaIdentity ca) {
        try {
            String caCertB64 = java.util.Base64.getEncoder().encodeToString(ca.getSubCaCertDer());
            CertDescInfo subCaInfo = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(caCertB64));
            SM2X509CertMaker maker = new SM2X509CertMaker();
            if (!ca.isBuiltin()) {
                maker.withIssuerKeys(caProvider.toPublicKey(ca), caProvider.toPrivateKey(ca));
            }
            X509CertificateHolder holder = maker.makeUserCertHolder(keyPair, dto, subCaInfo);
            X509Certificate userCert = SM2CertUtil.convertToX509Certificate(holder.getEncoded());

            X509Certificate subCa = SM2CertUtil.convertToX509Certificate(caCertB64);
            userCert.verify(subCa.getPublicKey());
            String b64 = java.util.Base64.getEncoder().encodeToString(userCert.getEncoded());
            if (!SM2X509CertMaker.isTruested(b64, caCertB64)) {
                throw new CertException("SM2 用户证书验签失败");
            }

            char[] pwd = certConfig.getP12Password().toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, pwd);
            ks.setKeyEntry("alias", keyPair.getPrivate(), pwd, new java.security.cert.Certificate[]{userCert});

            byte[] p12     = toBytes(ks, pwd);
            byte[] certPem = SM2CertUtil.convertToPem(userCert);
            byte[] priPem  = toPriPem(keyPair);
            byte[] priKey  = toPriKey(keyPair);

            return new P12Bundle(p12, userCert.getEncoded(), certPem, priPem, priKey);
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("SM2 P12 生成失败", e);
            throw new CertException("SM2 P12 生成失败", e);
        }
    }

    /** T10：caId 空 → 内置 SM2；否则查 Provider，校验算法匹配。 */
    private CaIdentity resolveCa(String caId) {
        if (caId == null || caId.isBlank()) {
            return caProvider.getDefault(Algorithm.SM2);
        }
        CaIdentity ca = caProvider.findById(caId)
                .orElseThrow(() -> new CertException("CA 不存在: " + caId));
        if (ca.getAlgorithm() != Algorithm.SM2) {
            throw new CertException("CA 算法不匹配，期望 SM2，实际 " + ca.getAlgorithm() + " (" + caId + ")");
        }
        return ca;
    }

    private static byte[] toPriPem(KeyPair keyPair) {
        try {
            PrivateKeyInfo info = SM2X509CertMaker.convertPrivateKeyInfo(keyPair.getPrivate());
            return SM2X509CertMaker.toPriPem(info);
        } catch (Exception e) {
            throw new CertException("私钥 PEM 转换失败", e);
        }
    }

    private static byte[] toPriKey(KeyPair keyPair) {
        try {
            return SM2X509CertMaker.toPEMFormat(keyPair.getPrivate(), "PRIVATE KEY");
        } catch (Exception e) {
            throw new CertException("私钥 Key 转换失败", e);
        }
    }

    private static byte[] toBytes(KeyStore ks, char[] pwd) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            ks.store(baos, pwd);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new CertException("KeyStore 序列化失败", e);
        }
    }

    // ── 内部值类型 ────────────────────────────────────────
    private static final class P12Bundle {
        final byte[] p12;
        final byte[] certDer;
        final byte[] certPem;
        final byte[] priPem;
        final byte[] priKey;

        P12Bundle(byte[] p12, byte[] certDer, byte[] certPem, byte[] priPem, byte[] priKey) {
            this.p12     = p12;
            this.certDer = certDer;
            this.certPem = certPem;
            this.priPem  = priPem;
            this.priKey  = priKey;
        }
    }
}
