package com.open.jgm.pki.ca.cert.controller;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.request.CsrSubmitRequest;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import com.open.jgm.pki.ca.cert.service.EccCertService;
import com.open.jgm.pki.ca.cert.util.ZipDownloadHelper;
import com.open.jgm.pki.ca.cert.crypto.ECCx509CertMaker;
import com.open.jgm.pki.ca.framework.exception.BusinessException;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStreamReader;
import java.io.StringReader;

/**
 * ECC 证书签发控制器（重构版），支持 prime256v1 / brainpoolP256r1 / FRP256v1。
 */
@Api(tags = "ECC证书签发(v2)")
@ApiSupport(order = 12)
@RestController
@RequestMapping("/api/v2/cert")
@Slf4j
@RequiredArgsConstructor
public class EccCertController {

    private final EccCertService eccCertService;

    @PostMapping("/ecc-cert-issue/{curve}")
    @ApiOperationSupport(order = 1)
    @ApiOperation("生成ECC用户证书（指定曲线）")
    public Response<String> eccCertIssue(@PathVariable String curve,
                                         @Validated @RequestBody CertIssueRequest request) {
        ECCx509CertMaker.CurveType ct = parseCurve(curve);
        String cn = eccCertService.issueUserCertForCurve(ct, request);
        return Response.ok(cn);
    }

    @GetMapping("/download-ecc-cert/{curve}/{universalName}")
    @ApiOperationSupport(order = 2)
    @ApiOperation("下载ECC用户证书ZIP（指定曲线）")
    public void downloadEccCert(@PathVariable String curve,
                                @PathVariable String universalName,
                                HttpServletResponse response) {
        ECCx509CertMaker.CurveType ct = parseCurve(curve);
        CertIssuedResult cert  = eccCertService.getIssuedCertForCurve(ct, universalName);
        CaChainResult    chain = eccCertService.getCaChainForCurve(ct);
        ZipDownloadHelper.writeUserCertZip(response, universalName, cert, chain, "ecc." + curve + ".");
    }

    @PostMapping("/ecc-p10PemStr/{curve}")
    @ApiOperationSupport(order = 3)
    @ApiOperation("ECC提交P10(文本，指定曲线)")
    public Response<String> eccP10PemStr(@PathVariable String curve,
                                         @Validated @RequestBody CsrSubmitRequest request) {
        ECCx509CertMaker.CurveType ct = parseCurve(curve);
        try (PEMParser parser = new PEMParser(new StringReader(request.getP10PemStr()))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                return Response.error("请输入正确的CSR数据，p10解析失败");
            }
            String cn = eccCertService.issueUserCertByCSRForCurve(ct, csr.getEncoded());
            return Response.ok(cn);
        } catch (Exception e) {
            log.error("ECC P10文本签发失败 [{}]", curve, e);
            return Response.error("ECC证书生成失败");
        }
    }

    @PostMapping("/ecc-p10Upload/{curve}")
    @ApiOperationSupport(order = 4)
    @ApiOperation("ECC提交P10(文件，指定曲线)")
    public Response<String> eccP10Upload(@PathVariable String curve,
                                         @ApiParam(name = "file", required = true)
                                         @RequestParam("file") MultipartFile file) {
        ECCx509CertMaker.CurveType ct = parseCurve(curve);
        try {
            PKCS10CertificationRequest csr;
            try (PEMParser parser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
                Object obj = parser.readObject();
                if (!(obj instanceof PKCS10CertificationRequest)) {
                    return Response.error("请上传正确的CSR文件，p10解析失败");
                }
                csr = (PKCS10CertificationRequest) obj;
            }
            String cn = eccCertService.issueUserCertByCSRForCurve(ct, csr.getEncoded());
            return Response.ok(cn);
        } catch (Exception e) {
            log.error("ECC P10文件签发失败 [{}]", curve, e);
            return Response.error("ECC证书生成错误");
        }
    }

    @GetMapping("/download-ecc-ca/{curve}")
    @ApiOperationSupport(order = 5)
    @ApiOperation("ECC根证书下载（指定曲线）")
    public void eccCaDownload(@PathVariable String curve, HttpServletResponse response) {
        ECCx509CertMaker.CurveType ct = parseCurve(curve);
        CaChainResult chain = eccCertService.getCaChainForCurve(ct);
        ZipDownloadHelper.writeCaChainZip(response, "ecc." + curve + ".ca.chain", chain, "ecc." + curve + ".");
    }

    private static ECCx509CertMaker.CurveType parseCurve(String curve) {
        try {
            return ECCx509CertMaker.CurveType.fromUrlKey(curve);
        } catch (IllegalArgumentException e) {
            throw new BusinessException("不支持的曲线: " + curve + "，可选值: prime256v1 / brainpoolP256r1 / FRP256v1");
        }
    }
}
