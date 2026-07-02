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

package com.open.jgm.pki.ca.cert.inspect.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * T24：密钥检查请求。
 * <p>
 * 可单独提供私钥（仅返回算法/长度），或同时提供证书（额外校验密钥对匹配）。
 */
@Data
@ApiModel("密钥检查请求")
public class KeyInspectRequest implements Serializable {

    @ApiModelProperty(value = "私钥 PEM（PKCS#8 / EC / RSA / Encrypted PKCS#8）", required = true)
    private String privateKeyPem;

    @ApiModelProperty("证书 PEM 或 base64 DER（可选；提供时校验与私钥匹配）")
    private String certPemOrBase64;

    @ApiModelProperty("Encrypted PKCS#8 口令（可选）")
    private String password;
}
