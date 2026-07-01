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
