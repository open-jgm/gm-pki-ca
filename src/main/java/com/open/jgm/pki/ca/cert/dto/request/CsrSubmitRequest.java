package com.open.jgm.pki.ca.cert.dto.request;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

/**
 * CSR P10 文本提交请求 DTO。
 */
@Data
@ApiModel("P10 文本提交请求")
public class CsrSubmitRequest implements Serializable {

    @NotBlank(message = "P10 PEM 内容不能为空")
    @ApiModelProperty(value = "P10 PEM 文件文本内容", required = true)
    private String p10PemStr;
}
