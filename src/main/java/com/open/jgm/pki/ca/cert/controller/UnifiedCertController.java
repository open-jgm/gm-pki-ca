package com.open.jgm.pki.ca.cert.controller;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.crypto.ECCx509CertMaker;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.request.CsrGenerateRequest;
import com.open.jgm.pki.ca.cert.dto.request.CsrSignRequest;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import com.open.jgm.pki.ca.cert.dto.response.CsrParseResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.service.CsrGenerateService;
import com.open.jgm.pki.ca.cert.service.CsrParseService;
import com.open.jgm.pki.ca.cert.service.EccCertService;
import com.open.jgm.pki.ca.cert.service.ICertService;
import com.open.jgm.pki.ca.cert.service.RsaCertService;
import com.open.jgm.pki.ca.cert.service.Sm2CertService;
import com.open.jgm.pki.ca.cert.util.ZipDownloadHelper;
import com.open.jgm.pki.ca.framework.exception.BusinessException;
import com.open.jgm.pki.ca.framework.model.Response;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * T04：统一证书签发入口，按 {@code algorithm} 参数分发到 SM2/RSA/ECC 服务。
 * <p>
 * 端点：
 * <ul>
 *   <li>POST /api/v2/cert/issue?algorithm=SM2|RSA|ECC&amp;curve=prime256v1 — 统一签发</li>
 *   <li>GET  /api/v2/cert/download/{algorithm}/{universalName}?curve=... — 统一下载 ZIP</li>
 * </ul>
 * ECC 算法可携带 {@code curve} 查询参数，默认 prime256v1。
 */
@Api(tags = "统一证书签发(v2)")
@ApiSupport(order = 5)
@RestController
@RequestMapping("/api/v2/cert")
@Slf4j
public class UnifiedCertController {

    private final ICertService sm2CertService;
    private final ICertService rsaCertService;
    private final EccCertService eccCertService;
    private final CsrParseService csrParseService;
    private final CsrGenerateService csrGenerateService;
    private final Sm2CertService sm2CertServiceConcrete;
    private final RsaCertService rsaCertServiceConcrete;

    public UnifiedCertController(@Qualifier("sm2CertService") ICertService sm2CertService,
                                 @Qualifier("rsaCertService") ICertService rsaCertService,
                                 EccCertService eccCertService,
                                 CsrParseService csrParseService,
                                 CsrGenerateService csrGenerateService,
                                 Sm2CertService sm2CertServiceConcrete,
                                 RsaCertService rsaCertServiceConcrete) {
        this.sm2CertService = sm2CertService;
        this.rsaCertService = rsaCertService;
        this.eccCertService = eccCertService;
        this.csrParseService = csrParseService;
        this.csrGenerateService = csrGenerateService;
        this.sm2CertServiceConcrete = sm2CertServiceConcrete;
        this.rsaCertServiceConcrete = rsaCertServiceConcrete;
    }

    @PostMapping("/issue")
    @ApiOperationSupport(order = 1)
    @ApiOperation("统一签发入口（按 algorithm 分发）")
    public Response<String> issue(
            @RequestParam(value = "algorithm", required = false) String algorithm,
            @RequestParam(value = "curve", required = false) String curve,
            @Validated @RequestBody CertIssueRequest request) {

        Algorithm algo = resolveAlgorithm(algorithm, request);
        String cn = switch (algo) {
            case SM2 -> sm2CertService.issueUserCert(request);
            case RSA -> rsaCertService.issueUserCert(request);
            case ECC -> eccCertService.issueUserCertForCurve(parseCurve(curve), request);
        };
        return Response.ok(cn);
    }

    @GetMapping("/download/{algorithm}/{universalName}")
    @ApiOperationSupport(order = 2)
    @ApiOperation("统一下载入口（按 algorithm 分发）")
    public void download(@PathVariable("algorithm") String algorithm,
                         @PathVariable("universalName") String universalName,
                         @RequestParam(value = "curve", required = false) String curve,
                         HttpServletResponse response) {

        Algorithm algo = Algorithm.parseOrNull(algorithm);
        if (algo == null) {
            throw new BusinessException("algorithm 不能为空");
        }

        CertIssuedResult cert;
        CaChainResult chain;
        String prefix;
        switch (algo) {
            case SM2 -> {
                cert = sm2CertService.getIssuedCert(universalName);
                chain = sm2CertService.getCaChain();
                prefix = "sm2.";
            }
            case RSA -> {
                cert = rsaCertService.getIssuedCert(universalName);
                chain = rsaCertService.getCaChain();
                prefix = "rsa.";
            }
            case ECC -> {
                ECCx509CertMaker.CurveType ct = parseCurve(curve);
                cert = eccCertService.getIssuedCertForCurve(ct, universalName);
                chain = eccCertService.getCaChainForCurve(ct);
                prefix = "ecc." + ct.getUrlKey() + ".";
            }
            default -> throw new CertException("不支持的算法: " + algo);
        }
        ZipDownloadHelper.writeUserCertZip(response, universalName, cert, chain, prefix);
    }

    @PostMapping("/csr/parse")
    @ApiOperationSupport(order = 3)
    @ApiOperation("T05：解析 PKCS#10 CSR（支持 SM2/RSA/ECC，DER-base64 或 PEM 文本）")
    public Response<CsrParseResult> parseCsr(@RequestBody String csrContent) {
        return Response.ok(csrParseService.parse(csrContent));
    }

    @PostMapping("/csr/generate")
    @ApiOperationSupport(order = 4)
    @ApiOperation("根据 DN 生成 SM2 PKCS#10 CSR 并下载")
    public void generateCsr(@Validated @RequestBody CsrGenerateRequest request,
                            HttpServletResponse response) {
        CsrGenerateService.GeneratedCsr generated = csrGenerateService.generate(request);
        ZipDownloadHelper.writeCsrZip(response,
                generated.commonName(),
                generated.csrPem(),
                generated.privateKeyPem());
    }

    @PostMapping("/csr/preview")
    @ApiOperationSupport(order = 5)
    @ApiOperation("T06：CSR 两步签发-预览。返回解析视图 + 服务端将应用的扩展（不实际签发）")
    public Response<CsrParseResult> previewCsrSign(@Validated @RequestBody CsrSignRequest request) {
        // Preview 复用 CsrParseService。已请求扩展从 CSR 中读出；
        // 推荐扩展按检测到的算法返回。前端可在此基础上调用 /csr/sign 并附加 overrides。
        return Response.ok(csrParseService.parse(request.getCsrContent()));
    }

    @PostMapping("/csr/sign")
    @ApiOperationSupport(order = 6)
    @ApiOperation("T06：CSR 两步签发-签发。在 CSR 基础上追加 KeyUsage / EKU / SAN / BC 扩展并出证")
    public Response<String> signCsr(@Validated @RequestBody CsrSignRequest request) {
        try {
            byte[] csrBytes = parseCsrToDer(request.getCsrContent());

            // 算法：请求显式 > CSR 自动检测
            Algorithm algo = Algorithm.parseOrNull(request.getAlgorithm());
            if (algo == null) {
                algo = Algorithm.valueOf(csrParseService.parse(request.getCsrContent()).getDetectedAlgorithm());
            }

            CertCreateDTO overrides = buildOverrides(request);

            String cn = switch (algo) {
                case SM2 -> sm2CertServiceConcrete.issueUserCertByCSRWithOverrides(csrBytes, overrides);
                case RSA -> rsaCertServiceConcrete.issueUserCertByCSRWithOverrides(csrBytes, overrides);
                case ECC -> eccCertService.issueUserCertByCSRForCurveWithOverrides(
                        parseCurve(request.getCurve()), csrBytes, overrides);
            };
            return Response.ok(cn);
        } catch (CertException | BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("T06 CSR 签发失败", e);
            throw new CertException("CSR 签发失败：" + e.getMessage(), e);
        }
    }

    // ── helpers ───────────────────────────────────────────

    private byte[] parseCsrToDer(String content) throws Exception {
        PKCS10CertificationRequest csr = csrParseService.readCsr(content);
        return csr.getEncoded();
    }

    private static CertCreateDTO buildOverrides(CsrSignRequest req) {
        CertCreateDTO dto = new CertCreateDTO();
        dto.setKeyUsages(req.getKeyUsages());
        dto.setExtendedKeyUsages(req.getExtendedKeyUsages());
        dto.setSubjectAltNames(req.getSubjectAltNames());
        dto.setBasicConstraintsCA(req.getBasicConstraintsCA());
        // certValidMonth 字段保留供 maker 后续扩展使用；当前 maker 不消费 CSR 路径的有效期覆盖
        if (req.getCertValidMonth() != null) {
            dto.setCertValidMonth(req.getCertValidMonth());
        }
        return dto;
    }

    private static Algorithm resolveAlgorithm(String queryParam, CertIssueRequest request) {
        Algorithm algo = Algorithm.parseOrNull(queryParam);
        if (algo == null) {
            algo = request.resolveAlgorithm();
        }
        if (algo == null) {
            throw new BusinessException("algorithm 不能为空（query 或 body 必须提供 SM2/RSA/ECC）");
        }
        return algo;
    }

    private static ECCx509CertMaker.CurveType parseCurve(String curve) {
        if (curve == null || curve.isBlank()) {
            return ECCx509CertMaker.CurveType.PRIME256V1;
        }
        try {
            return ECCx509CertMaker.CurveType.fromUrlKey(curve);
        } catch (IllegalArgumentException e) {
            throw new BusinessException("不支持的曲线: " + curve + "，可选值: prime256v1 / brainpoolP256r1 / FRP256v1");
        }
    }
}
