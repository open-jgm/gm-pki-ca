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

package com.open.jgm.pki.ca.cert.ca.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

/**
 * T08：自建 CA 上传请求。
 * <p>
 * 两种上传形态二选一：
 * <ul>
 *   <li>P12：{@link #p12Base64} + {@link #p12Password}</li>
 *   <li>PEM：{@link #certPem} + {@link #privateKeyPem}</li>
 * </ul>
 * 同时提供时优先采用 P12；都未提供则 400。
 */
@Data
@ApiModel("自建 CA 上传请求")
public class CaUploadRequest implements Serializable {

    @NotBlank(message = "CA 名称不能为空")
    @ApiModelProperty(value = "CA 显示名称", required = true, example = "MyCorp Sub CA")
    private String name;

    @ApiModelProperty(value = "PKCS#12 文件（base64 编码）。优先于 PEM。")
    private String p12Base64;

    @ApiModelProperty(value = "P12 口令（与 p12Base64 配对）", example = "changeit-strong-password")
    private String p12Password;

    @ApiModelProperty(value = "子 CA 证书 PEM 文本（含 -----BEGIN CERTIFICATE----- 行）")
    private String certPem;

    @ApiModelProperty(value = "子 CA 私钥 PEM 文本（PKCS#8 优先；也支持 RSA / EC PEM）")
    private String privateKeyPem;

    @ApiModelProperty(value = "根 CA 证书 PEM 文本（可选）")
    private String rootCertPem;

    @ApiModelProperty(value = "ECC 曲线名（仅 algorithm=ECC 必填；自动推断时可空）",
            example = "prime256v1")
    private String curve;
}
