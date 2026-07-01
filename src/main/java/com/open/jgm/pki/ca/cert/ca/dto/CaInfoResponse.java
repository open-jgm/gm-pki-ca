package com.open.jgm.pki.ca.cert.ca.dto;

import com.open.jgm.pki.ca.cert.ca.CaIdentity;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Base64;

/**
 * T08：CA 元信息对外视图（不含私钥）。
 */
@Data
@AllArgsConstructor
@ApiModel("CA 元信息")
public class CaInfoResponse {

    @ApiModelProperty("CA 唯一 ID（内置：builtin:ALGO[:curve]；自建：custom:UUID）")
    private String caId;

    @ApiModelProperty("CA 显示名称")
    private String name;

    @ApiModelProperty("算法 SM2 / RSA / ECC")
    private String algorithm;

    @ApiModelProperty("ECC 曲线名（仅 ECC 非空）")
    private String curve;

    @ApiModelProperty("Subject CN（解析自子 CA 证书）")
    private String subjectCn;

    @ApiModelProperty("证书序列号（hex）")
    private String serialNumberHex;

    @ApiModelProperty("是否内置 CA")
    private Boolean builtin;

    @ApiModelProperty("创建时间（毫秒）")
    private Long createdAt;

    @ApiModelProperty("子 CA 证书 PEM（base64 of DER 也即可下载）")
    private String subCaCertB64;

    public static CaInfoResponse from(CaIdentity ca) {
        String subB64 = Base64.getEncoder().encodeToString(ca.getSubCaCertDer());
        String cn = "";
        String serial = "";
        try {
            var detail = CertParseUtil.parse(subB64);
            cn = detail.getUniversalName();
            serial = detail.getSerialNumberHex();
        } catch (Exception ignored) {
            // 解析失败时返回空串，不阻断列出
        }
        return new CaInfoResponse(
                ca.getCaId(),
                ca.getName(),
                ca.getAlgorithm().name(),
                ca.getCurve(),
                cn,
                serial,
                ca.isBuiltin(),
                ca.getCreatedAt(),
                subB64);
    }
}
