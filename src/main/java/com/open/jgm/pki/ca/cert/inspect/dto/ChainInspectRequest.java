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
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * T25：证书链验证请求。
 */
@Data
@ApiModel("证书链验证请求")
public class ChainInspectRequest implements Serializable {

    @NotEmpty(message = "证书链不能为空")
    @ApiModelProperty(value = "证书链（PEM 或 base64 DER 列表），约定从终端实体 → 根 CA 顺序", required = true)
    private List<String> chain;

    @ApiModelProperty("信任锚集合（PEM 或 base64 DER）；为空时仅做相邻签名验证，不做根校验")
    private List<String> trustAnchors;
}
