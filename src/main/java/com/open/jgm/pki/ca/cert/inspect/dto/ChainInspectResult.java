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

import java.util.List;

/**
 * T25：证书链验证结果。
 */
@Data
@Builder
@AllArgsConstructor
@ApiModel("证书链验证结果")
public class ChainInspectResult {

    @ApiModelProperty("整条链是否信任（false 时检查 brokenAtIndex / reason）")
    private Boolean trusted;

    @ApiModelProperty("链断裂位置：终端实体=0；为 null 表示无断裂")
    private Integer brokenAtIndex;

    @ApiModelProperty("断裂或失败原因")
    private String reason;

    @ApiModelProperty("各证书的 Subject / Issuer / 序列号摘要")
    private List<Node> nodes;

    @Data
    @Builder
    @AllArgsConstructor
    @ApiModel("链节点摘要")
    public static class Node {
        private Integer index;
        private String subject;
        private String issuer;
        private String serialNumberHex;
        private String notBefore;
        private String notAfter;
        private Boolean signatureVerified;
    }
}
