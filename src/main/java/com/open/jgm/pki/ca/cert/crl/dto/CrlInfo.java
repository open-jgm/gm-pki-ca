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

package com.open.jgm.pki.ca.cert.crl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * T27：CRL 解析视图。
 */
@Data
@Builder
@AllArgsConstructor
@ApiModel("CRL 解析结果")
public class CrlInfo {

    @ApiModelProperty("CRL 版本")
    private Integer version;

    @ApiModelProperty("签发者 DN")
    private String issuer;

    @ApiModelProperty("签名算法 OID")
    private String signatureAlgorithmOid;

    @ApiModelProperty("本次更新时间（ISO-8601）")
    private String thisUpdate;

    @ApiModelProperty("下次更新时间（ISO-8601）")
    private String nextUpdate;

    @ApiModelProperty("吊销条目数")
    private Integer revokedCount;

    @ApiModelProperty("吊销条目列表")
    private List<RevokedView> revoked;

    @Data
    @Builder
    @AllArgsConstructor
    @ApiModel("CRL 吊销条目视图")
    public static class RevokedView {
        private String serialNumberHex;
        private String revocationDate;
        private Integer reason;
    }
}
