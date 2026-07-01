package com.open.jgm.pki.ca.cert.envelope;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * T19：信封解析视图。
 */
@Data
@Builder
@AllArgsConstructor
@ApiModel("数字信封解析结果")
public class EnvelopeInfo {

    @ApiModelProperty("信封版本号")
    private Integer version;

    @ApiModelProperty("内容加密算法 OID（SM4-CBC=1.2.156.10197.1.104.2 / AES-128-CBC=2.16.840.1.101.3.4.1.2）")
    private String contentEncryptionAlgorithmOid;

    @ApiModelProperty("内容加密算法可读名")
    private String contentEncryptionAlgorithmName;

    @ApiModelProperty("加密内容长度（字节）")
    private Integer encryptedContentLength;

    @ApiModelProperty("IV 长度（字节）")
    private Integer ivLength;

    @ApiModelProperty("收件人列表（issuer + 序列号 + 算法）")
    private List<RecipientView> recipients;

    @Data
    @Builder
    @AllArgsConstructor
    @ApiModel("信封单个收件人")
    public static class RecipientView {
        @ApiModelProperty("收件人证书签发者 DN")
        private String issuer;
        @ApiModelProperty("收件人证书序列号（hex）")
        private String serialNumberHex;
        @ApiModelProperty("密钥加密算法 OID（SM2=1.2.156.10197.1.301.3 / RSA=1.2.840.113549.1.1.1）")
        private String keyEncryptionAlgorithmOid;
        @ApiModelProperty("密钥加密算法可读名")
        private String keyEncryptionAlgorithmName;
        @ApiModelProperty("加密后的会话密钥长度（字节）")
        private Integer encryptedKeyLength;
    }
}
