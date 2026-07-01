package com.open.jgm.pki.ca.cert.inspect.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * T24：密钥检查请求。
 * <p>
 * 可单独提供私钥（仅返回算法/长度），或同时提供证书（额外校验密钥对匹配）。
 */
@Data
@ApiModel("密钥检查请求")
public class KeyInspectRequest implements Serializable {

    @ApiModelProperty(value = "私钥 PEM（PKCS#8 / EC / RSA / Encrypted PKCS#8）", required = true)
    private String privateKeyPem;

    @ApiModelProperty("证书 PEM 或 base64 DER（可选；提供时校验与私钥匹配）")
    private String certPemOrBase64;

    @ApiModelProperty("Encrypted PKCS#8 口令（可选）")
    private String password;
}
