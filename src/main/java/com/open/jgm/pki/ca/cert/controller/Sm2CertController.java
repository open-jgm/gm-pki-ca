/*
 * Copyright 2026 open-gm-jca contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.open.jgm.pki.ca.cert.controller;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.request.CsrSubmitRequest;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import com.open.jgm.pki.ca.cert.service.ICertService;
import com.open.jgm.pki.ca.cert.util.ZipDownloadHelper;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStreamReader;

/**
 * SM2 证书签发控制器（重构版）。
 * <p>
 * 端点前缀 /api/v2/cert，业务逻辑全部委托给 Sm2CertService。
 */
@Api(tags = "SM2证书签发(v2)")
@ApiSupport(order = 10)
@RestController
@RequestMapping("/api/v2/cert")
@Slf4j
public class Sm2CertController {

    private final ICertService sm2CertService;

    public Sm2CertController(@Qualifier("sm2CertService") ICertService sm2CertService) {
        this.sm2CertService = sm2CertService;
    }

    @PostMapping("/cert-issue")
    @ApiOperationSupport(order = 1)
    @ApiOperation("生成SM2用户证书")
    public Response<String> issueUserCert(@Validated @RequestBody CertIssueRequest request) {
        String cn = sm2CertService.issueUserCert(request);
        return Response.ok(cn);
    }

    @GetMapping("/download-cert/{universalName}")
    @ApiOperationSupport(order = 2)
    @ApiOperation("下载SM2用户证书ZIP")
    public void downloadUserCert(@PathVariable String universalName, HttpServletResponse response) {
        CertIssuedResult cert   = sm2CertService.getIssuedCert(universalName);
        CaChainResult    chain  = sm2CertService.getCaChain();
        ZipDownloadHelper.writeUserCertZip(response, universalName, cert, chain, "sm2.");
    }

    @PostMapping("/p10Upload")
    @ApiOperationSupport(order = 3)
    @ApiOperation("提交P10文件签发SM2证书")
    public Response<String> p10Upload(
            @ApiParam(name = "file", required = true, value = "P10文件(PEM格式)")
            @RequestParam("file") MultipartFile file) {
        try {
            PKCS10CertificationRequest csr;
            try (PEMParser parser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
                Object obj = parser.readObject();
                if (!(obj instanceof PKCS10CertificationRequest)) {
                    return Response.error("请上传正确的CSR文件，p10解析失败");
                }
                csr = (PKCS10CertificationRequest) obj;
            }
            String cn = sm2CertService.issueUserCertByCSR(csr.getEncoded());
            return Response.ok(cn);
        } catch (Exception e) {
            log.error("SM2 P10文件签发失败", e);
            return Response.error("证书生成错误");
        }
    }

    @PostMapping("/p10PemStr")
    @ApiOperationSupport(order = 4)
    @ApiOperation("提交P10文本签发SM2证书")
    public Response<String> p10PemStr(@Validated @RequestBody CsrSubmitRequest request) {
        try (PEMParser parser = new PEMParser(new java.io.StringReader(request.getP10PemStr()))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                return Response.error("请输入正确的CSR数据，p10解析失败");
            }
            String cn = sm2CertService.issueUserCertByCSR(csr.getEncoded());
            return Response.ok(cn);
        } catch (Exception e) {
            log.error("SM2 P10文本签发失败", e);
            return Response.error("证书生成失败");
        }
    }

    @GetMapping("/download-sm2-ca")
    @ApiOperationSupport(order = 5)
    @ApiOperation("SM2根证书下载")
    public void caDownload(HttpServletResponse response) {
        CaChainResult chain = sm2CertService.getCaChain();
        ZipDownloadHelper.writeCaChainZip(response, "sm2.ca.chain", chain, "sm2.");
    }

    @PostMapping("/parse-cert")
    @ApiOperationSupport(order = 6)
    @ApiOperation("解析证书内容")
    public Response<?> parseCert(@RequestBody String base64Cert) {
        return Response.ok(sm2CertService.parseCert(base64Cert.trim()));
    }
}
