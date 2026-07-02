/*
 * Copyright 2026 open-gm-jca contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.open.jgm.pki.ca.cert.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.io.Serializable;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * 证书签发请求 DTO（驼峰字段，兼容旧版下划线字段）。
 * <p>
 * T01 新增字段：{@link #algorithm} / {@link #certUsage} / {@link #signatureAlg}
 * / {@link #digestAlg} / {@link #outputFormats}。
 */
@Data
@ApiModel("证书签发请求")
public class CertIssueRequest implements Serializable {

    @NotBlank(message = "DN_CN 不能为空")
    @ApiModelProperty(value = "证书主体 CN（唯一标识）", required = true, example = "张三")
    @JsonAlias("dn_cn")
    private String dnCn;

    @NotBlank(message = "DN_C 不能为空")
    @ApiModelProperty(value = "国家", required = true, example = "CN")
    @JsonAlias("dn_c")
    private String dnC;

    @ApiModelProperty(value = "省/市", example = "DEMO")
    @JsonAlias("dn_st")
    private String dnSt;

    @ApiModelProperty(value = "市/县", example = "DEMO")
    @JsonAlias("dn_l")
    private String dnL;

    @ApiModelProperty(value = "街道地址")
    @JsonAlias("dn_street")
    private String dnStreet;

    @ApiModelProperty(value = "单位")
    @JsonAlias("dn_o")
    private String dnO;

    @ApiModelProperty(value = "部门")
    @JsonAlias("dn_ou")
    private String dnOu;

    @Email(message = "邮箱格式不正确")
    @ApiModelProperty(value = "邮箱")
    @JsonAlias("dn_email")
    private String dnEmail;

    @NotNull(message = "证书有效月数不能为空")
    @Min(value = 1, message = "有效月数不能小于 1")
    @Max(value = 360, message = "有效月数不能超过 360")
    @ApiModelProperty(value = "证书有效月数", required = true, example = "240")
    @JsonAlias("certValidMonth")
    private Integer certValidMonth;

    // ── T01 新增字段 ────────────────────────────────────────

    @ApiModelProperty(value = "证书算法（可选）；SM2 / RSA / ECC。未指定时使用 Controller 默认。",
            example = "SM2", allowableValues = "SM2, RSA, ECC")
    private String algorithm;

    @ApiModelProperty(value = "证书用途（可选）；SIGN（仅签名）/ ENC（仅加密）/ BOTH（签名+加密双证书）。"
            + "默认：SM2 → BOTH，RSA/ECC → SIGN。",
            example = "BOTH", allowableValues = "SIGN, ENC, BOTH")
    @JsonAlias("cert_usage")
    private String certUsage;

    @ApiModelProperty(value = "签名算法名（可选，T02 起生效）。如：SM3withSM2、SHA256withRSA、SHA256withECDSA。",
            example = "SM3withSM2")
    @JsonAlias({"signatureAlg", "signature_alg", "sigAlg"})
    private String signatureAlg;

    @ApiModelProperty(value = "摘要/哈希算法名（可选，T02 起生效）。如：SM3、SHA-256、SHA-1。",
            example = "SM3")
    @JsonAlias({"digestAlg", "digest_alg", "hashAlg"})
    private String digestAlg;

    @ApiModelProperty(value = "输出格式集合（可选）；空集合表示「全部」。可选：PEM / DER / P12 / JKS。",
            example = "[\"PEM\",\"P12\"]")
    @JsonAlias({"outputFormats", "output_formats", "formats"})
    private List<String> outputFormats;

    // ── T02 新增字段（X.509 扩展项） ────────────────────────────────────

    @ApiModelProperty(value = "KeyUsage 列表（可选，T02 起生效）。未指定按算法默认。"
            + "可选：digitalSignature / nonRepudiation / keyEncipherment / dataEncipherment "
            + "/ keyAgreement / keyCertSign / cRLSign / encipherOnly / decipherOnly。",
            example = "[\"digitalSignature\",\"keyEncipherment\"]")
    @JsonAlias({"keyUsages", "key_usages", "keyUsage", "key_usage"})
    private List<String> keyUsages;

    @ApiModelProperty(value = "ExtendedKeyUsage 列表（可选，T02 起生效）。未指定按算法默认。"
            + "可选：serverAuth / clientAuth / codeSigning / emailProtection / timeStamping / ocspSigning。",
            example = "[\"serverAuth\",\"clientAuth\"]")
    @JsonAlias({"extendedKeyUsages", "extended_key_usages", "ekuList", "eku"})
    private List<String> extendedKeyUsages;

    @ApiModelProperty(value = "BasicConstraints CA 标志（可选，T02 起生效）。"
            + "true → CA 证书；false → 终端实体；null → 终端实体（默认）。",
            example = "false")
    @JsonAlias({"basicConstraintsCA", "basic_constraints_ca", "isCa", "ca"})
    private Boolean basicConstraintsCA;

    @ApiModelProperty(value = "SubjectAltName 列表（可选，T02 起生效）。"
            + "每项形如 'type:value'，type ∈ dns/ip/email/rfc822/uri，无前缀默认 dns。",
            example = "[\"dns:example.com\",\"ip:192.168.1.1\",\"email:a@b.com\"]")
    @JsonAlias({"subjectAltNames", "subject_alt_names", "sans"})
    private List<String> subjectAltNames;

    // ── T10 新增字段（CA 选择） ──────────────────────────────────────

    @ApiModelProperty(value = "签发 CA 的 ID（T10）。未指定 → 算法默认内置 CA。"
            + "内置：builtin:SM2 / builtin:RSA / builtin:ECC:prime256v1；自建：custom:UUID。",
            example = "builtin:SM2")
    @JsonAlias({"caId", "ca_id"})
    private String caId;

    /** 内部使用，API 层不暴露 */
    @ApiModelProperty(hidden = true)
    private String p12Password;

    // ── 解析辅助方法（不做 Bean Validation，避免与 String 表示冲突） ──

    /** 解析 {@link #algorithm}；不合法时抛 IllegalArgumentException。 */
    public Algorithm resolveAlgorithm() {
        return Algorithm.parseOrNull(algorithm);
    }

    /** 解析 {@link #certUsage}；未指定返回 {@code null}（由调用方按算法填默认值）。 */
    public CertUsage resolveCertUsage() {
        return CertUsage.parseOrNull(certUsage);
    }

    /** 解析 {@link #outputFormats}；未指定时返回全部格式。 */
    public Set<OutputFormat> resolveOutputFormats() {
        if (outputFormats == null) {
            return EnumSet.allOf(OutputFormat.class);
        }
        return OutputFormat.parseOrAll(outputFormats);
    }
}
