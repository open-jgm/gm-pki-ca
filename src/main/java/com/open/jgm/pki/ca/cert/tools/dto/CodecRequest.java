package com.open.jgm.pki.ca.cert.tools.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

/**
 * T28：编码/解码请求。
 */
@Data
@ApiModel("编解码请求")
public class CodecRequest implements Serializable {

    @NotBlank(message = "operation 不能为空")
    @ApiModelProperty(value = "操作：encode / decode", required = true, example = "encode")
    private String operation;

    @NotBlank(message = "input 不能为空")
    @ApiModelProperty(value = "输入串", required = true)
    private String input;

    @ApiModelProperty("输入编码（仅 encode 时；plain/base64/hex；默认 plain）")
    private String inputEncoding;
}
