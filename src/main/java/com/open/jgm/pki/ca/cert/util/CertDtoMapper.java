package com.open.jgm.pki.ca.cert.util;

import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.response.CertDetailResult;

import java.util.EnumSet;
import java.util.Set;

/**
 * DTO 映射工具，集中管理新旧 DTO 之间的字段转换，消除三个 Service 中的重复代码。
 */
public final class CertDtoMapper {

    private CertDtoMapper() {}

    /**
     * 新版 {@link CertIssueRequest}（驼峰字段）→ 旧版 {@link CertCreateDTO}（下划线字段）。
     * <p>
     * T01 起额外透传 algorithm / certUsage / signatureAlg / digestAlg / outputFormats。
     * 当 {@code defaultUsage} 非空且请求未显式指定 certUsage 时，使用算法默认值。
     */
    public static CertCreateDTO toDto(CertIssueRequest req, CertUsage defaultUsage) {
        CertCreateDTO dto = new CertCreateDTO();
        dto.setDn_cn(req.getDnCn());
        dto.setDn_c(req.getDnC());
        dto.setDn_st(req.getDnSt());
        dto.setDn_l(req.getDnL());
        dto.setDn_street(req.getDnStreet());
        dto.setDn_email(req.getDnEmail());
        dto.setDn_o(req.getDnO());
        dto.setDn_ou(req.getDnOu());
        dto.setCertValidMonth(req.getCertValidMonth());

        // ── T01 新增字段透传 ──
        Algorithm algo = req.resolveAlgorithm();
        dto.setAlgorithm(algo);

        CertUsage usage = req.resolveCertUsage();
        dto.setCertUsage(usage != null ? usage : defaultUsage);

        dto.setSignatureAlg(blankToNull(req.getSignatureAlg()));
        dto.setDigestAlg(blankToNull(req.getDigestAlg()));

        Set<OutputFormat> formats = req.resolveOutputFormats();
        // 永不传 null：未指定 = 全格式，便于下游使用
        dto.setOutputFormats(formats == null || formats.isEmpty() ? EnumSet.allOf(OutputFormat.class) : formats);

        // ── T02 新增字段透传 ──
        dto.setKeyUsages(req.getKeyUsages());
        dto.setExtendedKeyUsages(req.getExtendedKeyUsages());
        dto.setBasicConstraintsCA(req.getBasicConstraintsCA());
        dto.setSubjectAltNames(req.getSubjectAltNames());

        // ── T10：CA 选择透传 ──
        dto.setCaId(blankToNull(req.getCaId()));
        return dto;
    }

    /**
     * 兼容旧调用：未指定 certUsage 默认值时退化到原行为（不补默认）。
     */
    public static CertCreateDTO toDto(CertIssueRequest req) {
        return toDto(req, null);
    }

    /**
     * 新版 {@link CertDetailResult} → 旧版 {@link CertDescInfo}（供 CertMaker 适配器使用）。
     */
    public static CertDescInfo toLegacyDescInfo(CertDetailResult detail) {
        CertDescInfo info = new CertDescInfo();
        info.setUniversalName(detail.getUniversalName());
        info.setOrganization(detail.getOrganization());
        info.setOrganizationUnit(detail.getOrganizationUnit());
        info.setCountry(detail.getCountry());
        info.setProvince(detail.getProvince());
        info.setCity(detail.getCity());
        info.setStreet(detail.getStreet());
        info.setEmail(detail.getEmail());
        info.setIssueOrg(detail.getIssueOrg());
        info.setCert(detail.getCert());
        info.setSerialNumberHex(detail.getSerialNumberHex());
        return info;
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
