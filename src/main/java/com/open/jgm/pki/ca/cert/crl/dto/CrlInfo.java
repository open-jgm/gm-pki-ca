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
