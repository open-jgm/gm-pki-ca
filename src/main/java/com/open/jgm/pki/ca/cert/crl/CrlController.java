package com.open.jgm.pki.ca.cert.crl;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.crl.dto.CrlGenerateRequest;
import com.open.jgm.pki.ca.cert.crl.dto.CrlInfo;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

/**
 * T26-T27：CRL 端点。
 */
@Api(tags = "CRL(v2)")
@ApiSupport(order = 40)
@RestController
@RequestMapping("/api/v2")
@RequiredArgsConstructor
public class CrlController {

    private final CrlService crlService;

    @PostMapping("/crl/generate")
    @ApiOperationSupport(order = 1)
    @ApiOperation("生成 CRL（按 caId + 被吊销序列号列表），返回 base64 DER")
    public Response<String> generate(@Valid @RequestBody CrlGenerateRequest req) {
        byte[] der = crlService.generate(req);
        return Response.ok(Base64.getEncoder().encodeToString(der));
    }

    @PostMapping("/inspect/crl")
    @ApiOperationSupport(order = 2)
    @ApiOperation("解析 CRL（base64 DER）")
    public Response<CrlInfo> parse(@RequestBody String base64Der) {
        if (base64Der == null || base64Der.isBlank()) {
            throw new CertException("base64Der 不能为空");
        }
        return Response.ok(crlService.parse(Base64.getDecoder().decode(base64Der.trim())));
    }
}
