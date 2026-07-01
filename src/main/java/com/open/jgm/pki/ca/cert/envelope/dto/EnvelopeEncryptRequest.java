package com.open.jgm.pki.ca.cert.envelope.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

/**
 * T20：信封加密请求。
 */
@Data
@ApiModel("信封加密请求")
public class EnvelopeEncryptRequest implements Serializable {

    @NotBlank(message = "明文不能为空")
    @ApiModelProperty(value = "明文 base64", required = true, example = "aGVsbG8gd29ybGQ=")
    private String plainBase64;

    @NotBlank(message = "收件人证书不能为空")
    @ApiModelProperty(value = "收件人证书（PEM 或 base64 DER）", required = true)
    private String recipientCert;
}
