package com.open.jgm.pki.ca.cert.dto.response;

import lombok.Builder;
import lombok.Value;

import java.util.List;

/**
 * T05：CSR 解析结果。
 * <p>
 * 从 PKCS#10 CSR 中提取 Subject / 公钥 / 签名算法 / 已请求扩展，并按算法给出推荐扩展。
 */
@Value
@Builder
public class CsrParseResult {

    /** 算法：SM2 / RSA / ECC（按公钥参数检测） */
    String detectedAlgorithm;

    /** Subject DN 全文 */
    String subjectDn;

    /** Subject CN（universalName） */
    String commonName;

    /** 公钥算法标识（OID 友好名，如 EC / RSA / SM2） */
    String publicKeyAlgorithm;

    /** 公钥参数描述（RSA → 位长；EC → 曲线名；SM2 → "SM2") */
    String publicKeyParam;

    /** 公钥 PEM 文本（SubjectPublicKeyInfo） */
    String publicKeyPem;

    /** CSR 自带签名算法（OID 友好名） */
    String signatureAlgorithm;

    /** CSR 中已请求的 KeyUsage 字符串列表（按 RFC 5280 名称） */
    List<String> requestedKeyUsages;

    /** CSR 中已请求的 ExtendedKeyUsage 名称列表 */
    List<String> requestedExtendedKeyUsages;

    /** CSR 中已请求的 SubjectAltName 列表（type:value） */
    List<String> requestedSubjectAltNames;

    /** CSR 中已请求的 BasicConstraints CA 标志，未指定为 null */
    Boolean requestedBasicConstraintsCA;

    /** 推荐 KeyUsage（按检测到的算法） */
    List<String> recommendedKeyUsages;

    /** 推荐 ExtendedKeyUsage（按检测到的算法） */
    List<String> recommendedExtendedKeyUsages;
}
