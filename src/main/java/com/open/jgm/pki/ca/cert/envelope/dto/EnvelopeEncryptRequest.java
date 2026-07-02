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
 * T20：信封加密请求。
 */
@Data
@ApiModel("信封加密请求")
public class EnvelopeEncryptRequest implements Serializable {

    @NotBlank(message = "明文不能为空")
    @ApiModelProperty(value = "明文 base64", required = true, example = "aGVsbG8gd29ybGQ=")
    private String plainBase64;

    @NotBlank(message = "收件人证书不能为空")
    @ApiModelProperty(value = "收件人证书（PEM 或 base64 DER）", required = true)
    private String recipientCert;
}
