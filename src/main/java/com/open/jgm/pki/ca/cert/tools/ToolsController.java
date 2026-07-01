package com.open.jgm.pki.ca.cert.tools;

import cn.hutool.core.util.HexUtil;
import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.tools.dto.CodecRequest;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * T28：编解码工具。
 * <p>
 * 端点：
 * <ul>
 *   <li>POST /api/v2/tools/base64 — operation=encode/decode</li>
 *   <li>POST /api/v2/tools/hex    — operation=encode/decode</li>
 *   <li>POST /api/v2/tools/asn1   — input 为 base64/hex DER，返回 ASN.1 树形文本</li>
 * </ul>
 * <p>
 * encode 时 {@code inputEncoding} 可选：
 * <ul>
 *   <li>plain（默认）：input 按 UTF-8 字节流处理</li>
 *   <li>base64：input 先 base64 解码得到字节，再 encode 到目标编码</li>
 *   <li>hex：input 先 hex 解码得到字节，再 encode 到目标编码</li>
 * </ul>
 */
@Api(tags = "编解码工具(v2)")
@ApiSupport(order = 50)
@RestController
@RequestMapping("/api/v2/tools")
public class ToolsController {

    @PostMapping("/base64")
    @ApiOperationSupport(order = 1)
    @ApiOperation("Base64 编解码")
    public Response<String> base64(@Valid @RequestBody CodecRequest req) {
        return Response.ok(doBase64(req));
    }

    @PostMapping("/hex")
    @ApiOperationSupport(order = 2)
    @ApiOperation("Hex 编解码")
    public Response<String> hex(@Valid @RequestBody CodecRequest req) {
        return Response.ok(doHex(req));
    }

    @PostMapping("/asn1")
    @ApiOperationSupport(order = 3)
    @ApiOperation("ASN.1 树形输出（输入 base64 / hex DER；优先 base64）")
    public Response<String> asn1(@RequestBody String input) {
        if (input == null || input.isBlank()) {
            throw new CertException("input 不能为空");
        }
        String s = input.trim();
        byte[] der = tryBase64ThenHex(s);
        return Response.ok(Asn1Dumper.dump(der));
    }

    // ──────────────────────────────────────────────────────────

    private static String doBase64(CodecRequest req) {
        String op = req.getOperation().trim().toLowerCase();
        if ("encode".equals(op)) {
            byte[] bytes = toBytes(req.getInput(), req.getInputEncoding());
            return Base64.getEncoder().encodeToString(bytes);
        }
        if ("decode".equals(op)) {
            try {
                byte[] decoded = Base64.getDecoder().decode(req.getInput().trim());
                return new String(decoded, StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new CertException("base64 解码失败: " + e.getMessage());
            }
        }
        throw new CertException("operation 必须为 encode / decode");
    }

    private static String doHex(CodecRequest req) {
        String op = req.getOperation().trim().toLowerCase();
        if ("encode".equals(op)) {
            byte[] bytes = toBytes(req.getInput(), req.getInputEncoding());
            return HexUtil.encodeHexStr(bytes);
        }
        if ("decode".equals(op)) {
            try {
                String s = stripPrefix(req.getInput().trim());
                byte[] decoded = HexUtil.decodeHex(s);
                return new String(decoded, StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new CertException("hex 解码失败: " + e.getMessage());
            }
        }
        throw new CertException("operation 必须为 encode / decode");
    }

    private static byte[] toBytes(String input, String inputEncoding) {
        if (input == null) {
            throw new CertException("input 不能为空");
        }
        String enc = inputEncoding == null ? "plain" : inputEncoding.trim().toLowerCase();
        return switch (enc) {
            case "", "plain" -> input.getBytes(StandardCharsets.UTF_8);
            case "base64"    -> safeBase64Decode(input);
            case "hex"       -> HexUtil.decodeHex(stripPrefix(input));
            default          -> throw new CertException("不支持的 inputEncoding: " + inputEncoding);
        };
    }

    private static byte[] safeBase64Decode(String s) {
        try {
            return Base64.getDecoder().decode(s.trim());
        } catch (Exception e) {
            throw new CertException("input 不是合法 base64: " + e.getMessage());
        }
    }

    private static byte[] tryBase64ThenHex(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (Exception ignored) {
            try {
                return HexUtil.decodeHex(stripPrefix(s));
            } catch (Exception e) {
                throw new CertException("input 既不是合法 base64 也不是合法 hex");
            }
        }
    }

    private static String stripPrefix(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) return s.substring(2);
        return s;
    }
}
