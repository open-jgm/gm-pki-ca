package com.open.jgm.pki.ca.cert.crl.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * T26：CRL 生成请求。
 */
@Data
@ApiModel("CRL 生成请求")
public class CrlGenerateRequest implements Serializable {

    @ApiModelProperty(value = "签发 CA 的 ID（默认 builtin:SM2）", example = "builtin:SM2")
    private String caId;

    @ApiModelProperty(value = "本次更新有效天数", example = "30")
    private Integer validDays;

    @NotEmpty(message = "被吊销条目不能为空")
    @ApiModelProperty(value = "被吊销条目列表", required = true)
    private List<RevokedEntry> revoked;

    @Data
    @ApiModel("CRL 被吊销条目")
    public static class RevokedEntry implements Serializable {

        @ApiModelProperty(value = "被吊销证书序列号（hex 字符串，允许 0x 前缀）", required = true, example = "1a2b3c")
        private String serialNumberHex;

        @ApiModelProperty(value = "吊销时间（ISO-8601；空 → 当前时间）")
        private String revocationDate;

        @ApiModelProperty(value = "吊销原因（0=未指定 1=keyCompromise 4=superseded 5=cessationOfOperation 等）",
                example = "1")
        private Integer reason;
    }
}
