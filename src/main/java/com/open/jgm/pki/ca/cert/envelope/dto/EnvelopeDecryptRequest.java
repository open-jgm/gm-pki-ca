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

package com.open.jgm.pki.ca.cert.envelope.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

/**
 * T20：信封解密请求。
 * <p>
 * 私钥来源二选一：
 * <ul>
 *   <li>{@link #p12Base64} + {@link #p12Password}（推荐：私钥与证书一并提供）</li>
 *   <li>{@link #privateKeyPem} + {@link #ownerCertPem}（拆分形式）</li>
 * </ul>
 */
@Data
@ApiModel("信封解密请求")
public class EnvelopeDecryptRequest implements Serializable {

    @NotBlank(message = "信封字节 base64 不能为空")
    @ApiModelProperty(value = "信封 DER 字节 base64", required = true)
    private String envelopeBase64;

    @ApiModelProperty("PKCS#12 文件 base64（与 p12Password 配对）")
    private String p12Base64;

    @ApiModelProperty(value = "P12 口令", example = "changeit-strong-password")
    private String p12Password;

    @ApiModelProperty("私钥 PEM 文本（PKCS#8 / RSA / EC）")
    private String privateKeyPem;

    @ApiModelProperty("拥有该私钥的证书 PEM（用于在多收件人信封中定位 recipientInfo；单收件人时可空）")
    private String ownerCertPem;
}
