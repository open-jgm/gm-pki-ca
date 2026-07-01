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
