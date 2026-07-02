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

package com.open.jgm.pki.ca.cert.tools.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

/**
 * T28：编码/解码请求。
 */
@Data
@ApiModel("编解码请求")
public class CodecRequest implements Serializable {

    @NotBlank(message = "operation 不能为空")
    @ApiModelProperty(value = "操作：encode / decode", required = true, example = "encode")
    private String operation;

    @NotBlank(message = "input 不能为空")
    @ApiModelProperty(value = "输入串", required = true)
    private String input;

    @ApiModelProperty("输入编码（仅 encode 时；plain/base64/hex；默认 plain）")
    private String inputEncoding;
}
