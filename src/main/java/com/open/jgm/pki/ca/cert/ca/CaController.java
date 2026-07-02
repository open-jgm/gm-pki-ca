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

package com.open.jgm.pki.ca.cert.ca;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.ca.dto.CaInfoResponse;
import com.open.jgm.pki.ca.cert.ca.dto.CaUploadRequest;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * T08：自建 CA 管理端点。
 * <p>
 * 路由前缀 {@code /api/v2/ca}，由 {@link AdminTokenInterceptor} 强制校验 {@code X-Admin-Token}（T11）。
 */
@Api(tags = "CA 管理(v2)")
@ApiSupport(order = 10)
@RestController
@RequestMapping("/api/v2/ca")
@RequiredArgsConstructor
@Slf4j
public class CaController {

    private final CaProvider caProvider;
    private final CaUploadService uploadService;

    @PostMapping(value = "/upload", consumes = {"multipart/form-data"})
    @ApiOperationSupport(order = 1)
    @ApiOperation("上传自建 CA（multipart/form-data；P12 文件 + 表单字段）")
    public Response<CaInfoResponse> uploadMultipart(
            @RequestParam(value = "name") String name,
            @RequestParam(value = "p12Password", required = false) String p12Password,
            @RequestParam(value = "curve", required = false) String curve,
            @RequestParam(value = "p12", required = false) MultipartFile p12) {
        CaUploadRequest req = new CaUploadRequest();
        req.setName(name);
        req.setP12Password(p12Password);
        req.setCurve(curve);
        return Response.ok(CaInfoResponse.from(uploadService.upload(req, p12)));
    }

    @PostMapping(value = "/upload", consumes = {"application/json"})
    @ApiOperationSupport(order = 2)
    @ApiOperation("上传自建 CA（JSON；p12Base64 或 certPem+privateKeyPem）")
    public Response<CaInfoResponse> uploadJson(@Valid @RequestBody CaUploadRequest request) {
        return Response.ok(CaInfoResponse.from(uploadService.upload(request, null)));
    }

    @GetMapping("/list")
    @ApiOperationSupport(order = 3)
    @ApiOperation("列出所有 CA（内置 + 自建）")
    public Response<List<CaInfoResponse>> list() {
        return Response.ok(caProvider.list().stream().map(CaInfoResponse::from).toList());
    }

    @GetMapping("/{caId}")
    @ApiOperationSupport(order = 4)
    @ApiOperation("查看单个 CA 详情")
    public Response<CaInfoResponse> get(@PathVariable("caId") String caId) {
        return caProvider.findById(caId)
                .map(CaInfoResponse::from)
                .map(Response::ok)
                .orElse(Response.error("404", "CA 不存在: " + caId));
    }

    @DeleteMapping("/{caId}")
    @ApiOperationSupport(order = 5)
    @ApiOperation("删除自建 CA（内置 CA 拒绝）")
    public Response<Void> delete(@PathVariable("caId") String caId) {
        caProvider.delete(caId);
        return Response.ok();
    }
}
