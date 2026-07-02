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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

/**
 * T24：密钥检查结果。
 */
@Data
@Builder
@AllArgsConstructor
@ApiModel("密钥检查结果")
public class KeyInspectResult {

    @ApiModelProperty("私钥算法（RSA / EC / SM2-EC）")
    private String algorithm;

    @ApiModelProperty("位长（RSA=模长；EC=曲线域宽）")
    private Integer bits;

    @ApiModelProperty("EC 曲线名（仅 EC 私钥）")
    private String curve;

    @ApiModelProperty("私钥与提供的证书是否匹配（未提供证书时为 null）")
    private Boolean matchCertificate;

    @ApiModelProperty("不匹配原因（仅 matchCertificate=false 时）")
    private String mismatchReason;
}
