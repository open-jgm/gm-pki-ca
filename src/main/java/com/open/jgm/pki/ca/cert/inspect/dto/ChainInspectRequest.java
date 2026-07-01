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
