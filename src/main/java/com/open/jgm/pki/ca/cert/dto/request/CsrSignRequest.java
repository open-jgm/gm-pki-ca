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

package com.open.jgm.pki.ca.cert.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * T06：CSR 两步签发请求体（同时用于 /csr/preview 与 /csr/sign）。
 * <p>
 * {@code /preview} 只读取 CSR，返回解析结果 + 服务端将应用的默认扩展（不签发）。
 * {@code /sign} 在 preview 基础上允许追加 KeyUsage / EKU / SAN / BC / 有效期，
 * 由 maker 在签发时合并到证书。
 */
@Data
@ApiModel("T06 CSR 两步签发请求")
public class CsrSignRequest implements Serializable {

    @NotBlank(message = "CSR 内容不能为空")
    @ApiModelProperty(value = "CSR 内容（base64 DER 或 PEM 文本均可）", required = true)
    @JsonAlias({"csrContent", "csr_content", "p10PemStr", "csr"})
    private String csrContent;

    @ApiModelProperty(value = "算法（可选）；未指定时按 CSR 公钥自动检测", allowableValues = "SM2, RSA, ECC")
    private String algorithm;

    @ApiModelProperty(value = "ECC 曲线（可选）；仅 algorithm=ECC 时生效，默认 prime256v1",
            allowableValues = "prime256v1, brainpoolP256r1, FRP256v1")
    private String curve;

    @ApiModelProperty("有效期（月）；未指定时使用配置默认")
    @JsonAlias("cert_valid_month")
    private Integer certValidMonth;

    @ApiModelProperty("追加 KeyUsage（合并/覆盖 CSR 中已请求）")
    @JsonAlias({"keyUsages", "key_usages", "keyUsage"})
    private List<String> keyUsages;

    @ApiModelProperty("追加 ExtendedKeyUsage")
    @JsonAlias({"extendedKeyUsages", "extended_key_usages", "eku"})
    private List<String> extendedKeyUsages;

    @ApiModelProperty("追加 SubjectAltName，每项 'type:value'")
    @JsonAlias({"subjectAltNames", "subject_alt_names", "sans"})
    private List<String> subjectAltNames;

    @ApiModelProperty("BasicConstraints CA 标志")
    @JsonAlias({"basicConstraintsCA", "isCa"})
    private Boolean basicConstraintsCA;
}
