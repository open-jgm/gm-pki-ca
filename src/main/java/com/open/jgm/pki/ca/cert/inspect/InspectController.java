package com.open.jgm.pki.ca.cert.inspect;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.dto.response.CertDetailResult;
import com.open.jgm.pki.ca.cert.dto.response.CsrParseResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.inspect.dto.ChainInspectRequest;
import com.open.jgm.pki.ca.cert.inspect.dto.ChainInspectResult;
import com.open.jgm.pki.ca.cert.inspect.dto.KeyInspectRequest;
import com.open.jgm.pki.ca.cert.inspect.dto.KeyInspectResult;
import com.open.jgm.pki.ca.cert.service.CsrParseService;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * T23-T25：检查端点。
 * <ul>
 *   <li>POST /api/v2/inspect/cert  — 解析证书（含 v3 扩展项 T22）</li>
 *   <li>POST /api/v2/inspect/csr   — 解析 PKCS#10 CSR</li>
 *   <li>POST /api/v2/inspect/key   — 私钥检查 + 私钥/证书匹配（T24）</li>
 *   <li>POST /api/v2/inspect/chain — 证书链信任路径验证（T25）</li>
 * </ul>
 */
@Api(tags = "检查工具(v2)")
@ApiSupport(order = 30)
@RestController
@RequestMapping("/api/v2/inspect")
@RequiredArgsConstructor
@Slf4j
public class InspectController {

    private final CsrParseService csrParseService;
    private final KeyInspectService keyInspectService;
    private final ChainInspectService chainInspectService;

    @PostMapping("/cert")
    @ApiOperationSupport(order = 1)
    @ApiOperation("证书解析（含 v3 扩展项）")
    public Response<CertDetailResult> parseCert(@RequestBody String certPemOrBase64) {
        if (certPemOrBase64 == null || certPemOrBase64.isBlank()) {
            throw new CertException("证书内容不能为空");
        }
        return Response.ok(CertParseUtil.parse(certPemOrBase64.trim()));
    }

    @PostMapping("/csr")
    @ApiOperationSupport(order = 2)
    @ApiOperation("CSR 解析（PEM 或 DER base64）")
    public Response<CsrParseResult> parseCsr(@RequestBody String csrContent) {
        return Response.ok(csrParseService.parse(csrContent));
    }

    @PostMapping("/key")
    @ApiOperationSupport(order = 3)
    @ApiOperation("私钥检查 + 私钥/证书匹配")
    public Response<KeyInspectResult> inspectKey(@Valid @RequestBody KeyInspectRequest request) {
        return Response.ok(keyInspectService.inspect(request));
    }

    @PostMapping("/chain")
    @ApiOperationSupport(order = 4)
    @ApiOperation("证书链信任路径验证")
    public Response<ChainInspectResult> inspectChain(@Valid @RequestBody ChainInspectRequest request) {
        return Response.ok(chainInspectService.inspect(request));
    }
}
