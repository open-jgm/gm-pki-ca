package com.open.jgm.pki.ca.cert.dto.internal;

import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.*;
import lombok.Data;


import java.io.Serializable;
import java.util.List;
import java.util.Set;

/**
 * @Author lt
 * @Description 证书生成入参
 **/
@Data
public class CertCreateDTO implements Serializable {
    @NotBlank(message = "证书名称不能为空")
    @ApiModelProperty("证书名称CN")
    private String dn_cn;
    @NotNull(message = "证书有效月份不能为空")
    @ApiModelProperty("证书有效月份")
    @Max(value = 360, message = "证书有效月份超出最大值")
    @Min(value = 1, message = "证书有效月份小于最小值")
    private Integer certValidMonth;
    @NotBlank(message = "国家名称不能为空")
    @ApiModelProperty("国家名称C")
    private String dn_c;
    // @NotBlank(message = "省份名称不能为空")
    @ApiModelProperty("省份名称ST")
    private String dn_st;
    // @NotBlank(message = "城市名称不能为空")
    @ApiModelProperty("城市名称L")
    private String dn_l;
    // @NotBlank(message = "街道名称不能为空")
    @ApiModelProperty("街道名称STREET")
    private String dn_street;
    // @NotBlank(message = "电子邮箱地址不能为空")
    @ApiModelProperty("电子邮箱地址E")
    @Email(message = "电子邮箱地址格式不正确")
    private String dn_email;
    @NotBlank(message = "组织机构名称不能为空")
    @ApiModelProperty("组织机构名称O")
    private String dn_o;
    @NotBlank(message = "组织机构单位名称不能为空")
    @ApiModelProperty("组织机构单位名称OU")
    private String dn_ou;
    @ApiModelProperty("P12文件密码")
    private String p12Password;

    // ── T01 新增字段（已解析为枚举，Service 层直接消费） ────────────────────

    /** 证书算法（可选）。Service 可校验与自身一致性。 */
    @ApiModelProperty("证书算法 SM2/RSA/ECC")
    private Algorithm algorithm;

    /** 证书用途；由 Service 在 mapper 层补默认（SM2→BOTH, RSA/ECC→SIGN）。 */
    @ApiModelProperty("证书用途 SIGN/ENC/BOTH")
    private CertUsage certUsage;

    /** 签名算法名（T02 起生效）。 */
    @ApiModelProperty("签名算法名（T02 起生效）")
    private String signatureAlg;

    /** 摘要算法名（T02 起生效）。 */
    @ApiModelProperty("摘要算法名（T02 起生效）")
    private String digestAlg;

    /** 输出格式集合（T03 起按需打包）。 */
    @ApiModelProperty("输出格式集合 PEM/DER/P12/JKS")
    private Set<OutputFormat> outputFormats;

    // ── T02 新增字段（X.509 v3 扩展） ────────────────────────────

    /** KeyUsage 列表（字符串原值，maker 内解析）；空/null → 使用算法默认。 */
    @ApiModelProperty("KeyUsage 列表（T02）")
    private List<String> keyUsages;

    /** ExtendedKeyUsage 列表（字符串原值，maker 内解析）；空/null → 使用算法默认。 */
    @ApiModelProperty("ExtendedKeyUsage 列表（T02）")
    private List<String> extendedKeyUsages;

    /** BasicConstraints CA 标志（true=CA, false/null=EE）。 */
    @ApiModelProperty("BasicConstraints CA 标志（T02）")
    private Boolean basicConstraintsCA;

    /** SubjectAltName 列表，每项 "type:value"。 */
    @ApiModelProperty("SubjectAltName 列表（T02）")
    private List<String> subjectAltNames;

    // ── T10：签发 CA 选择 ──────────────────────────────
    /** 签发 CA 的 ID（null → 算法默认内置 CA）。 */
    @ApiModelProperty("签发 CA 的 ID（T10）")
    private String caId;
}
