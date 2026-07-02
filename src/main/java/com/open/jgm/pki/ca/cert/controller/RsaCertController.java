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
import java.io.StringReader;

/**
 * RSA 证书签发控制器（重构版）。
 */
@Api(tags = "RSA证书签发(v2)")
@ApiSupport(order = 11)
@RestController
@RequestMapping("/api/v2/cert")
@Slf4j
public class RsaCertController {

    private final ICertService rsaCertService;

    public RsaCertController(@Qualifier("rsaCertService") ICertService rsaCertService) {
        this.rsaCertService = rsaCertService;
    }

    @PostMapping("/rsa-cert-issue")
    @ApiOperationSupport(order = 1)
    @ApiOperation("生成RSA用户证书")
    public Response<String> rsaCertIssue(@Validated @RequestBody CertIssueRequest request) {
        String cn = rsaCertService.issueUserCert(request);
        return Response.ok(cn);
    }

    @GetMapping("/download-rsa-cert/{universalName}")
    @ApiOperationSupport(order = 2)
    @ApiOperation("下载RSA用户证书ZIP")
    public void downloadRsaCert(@PathVariable String universalName, HttpServletResponse response) {
        CertIssuedResult cert  = rsaCertService.getIssuedCert(universalName);
        CaChainResult    chain = rsaCertService.getCaChain();
        ZipDownloadHelper.writeUserCertZip(response, universalName, cert, chain, "rsa.");
    }

    @PostMapping("/rsa-p10PemStr")
    @ApiOperationSupport(order = 3)
    @ApiOperation("RSA提交P10(文本)")
    public Response<String> rsaP10PemStr(@Validated @RequestBody CsrSubmitRequest request) {
        try (PEMParser parser = new PEMParser(new StringReader(request.getP10PemStr()))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                return Response.error("请输入正确的CSR数据，p10解析失败");
            }
            String cn = rsaCertService.issueUserCertByCSR(csr.getEncoded());
            return Response.ok(cn);
        } catch (Exception e) {
            log.error("RSA P10文本签发失败", e);
            return Response.error("RSA证书生成失败");
        }
    }

    @PostMapping("/rsa-p10Upload")
    @ApiOperationSupport(order = 4)
    @ApiOperation("RSA提交P10(文件)")
    public Response<String> rsaP10Upload(
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
            String cn = rsaCertService.issueUserCertByCSR(csr.getEncoded());
            return Response.ok(cn);
        } catch (Exception e) {
            log.error("RSA P10文件签发失败", e);
            return Response.error("RSA证书生成错误");
        }
    }

    @GetMapping("/download-rsa-ca")
    @ApiOperationSupport(order = 5)
    @ApiOperation("RSA根证书下载")
    public void rsaCaDownload(HttpServletResponse response) {
        CaChainResult chain = rsaCertService.getCaChain();
        ZipDownloadHelper.writeCaChainZip(response, "rsa.ca.chain", chain, "rsa.");
    }
}
