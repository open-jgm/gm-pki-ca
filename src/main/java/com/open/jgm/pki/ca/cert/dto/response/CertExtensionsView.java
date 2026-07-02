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

package com.open.jgm.pki.ca.cert.dto.response;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * T22：X.509 v3 扩展项视图（解析 KU / EKU / SAN / AKI / SKI / BC）。
 */
@Data
@ApiModel("证书 v3 扩展项")
public class CertExtensionsView implements Serializable {

    @ApiModelProperty("KeyUsage（按 RFC 5280 顺序的可读名集合）")
    private List<String> keyUsages;

    @ApiModelProperty("ExtendedKeyUsage（可读名集合，未知项以 OID 字符串呈现）")
    private List<String> extendedKeyUsages;

    @ApiModelProperty("SubjectAltName 列表，每项 'type:value'，type ∈ dns/ip/email/rfc822/uri/dirName/other")
    private List<String> subjectAltNames;

    @ApiModelProperty("AuthorityKeyIdentifier(hex)")
    private String authorityKeyIdentifierHex;

    @ApiModelProperty("SubjectKeyIdentifier(hex)")
    private String subjectKeyIdentifierHex;

    @ApiModelProperty("BasicConstraints CA 标志（true=CA, false=终端实体, null=未声明）")
    private Boolean basicConstraintsCA;

    @ApiModelProperty("BasicConstraints pathLenConstraint（仅 CA=true 时有意义）")
    private Integer basicConstraintsPathLen;
}
