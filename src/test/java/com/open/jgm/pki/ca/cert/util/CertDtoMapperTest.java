package com.open.jgm.pki.ca.cert.util;

import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 验证 T01 新增的 5 个字段（algorithm/certUsage/signatureAlg/digestAlg/outputFormats）
 * 在请求 → 内部 DTO 的映射过程中正确透传与默认值填充。
 */
class CertDtoMapperTest {

    private static CertIssueRequest baseRequest() {
        CertIssueRequest req = new CertIssueRequest();
        req.setDnCn("张三");
        req.setDnC("CN");
        req.setDnSt("hunan");
        req.setDnL("changsha");
        req.setDnO("openCA");
        req.setDnOu("dev");
        req.setCertValidMonth(12);
        return req;
    }

    @Test
    void toDto_legacyFieldsPreserved() {
        CertIssueRequest req = baseRequest();
        CertCreateDTO dto = CertDtoMapper.toDto(req);

        assertThat(dto.getDn_cn()).isEqualTo("张三");
        assertThat(dto.getDn_c()).isEqualTo("CN");
        assertThat(dto.getCertValidMonth()).isEqualTo(12);
    }

    @Test
    void toDto_unspecifiedNewFields_useFallbacks() {
        CertIssueRequest req = baseRequest();
        // 不指定任何新字段
        CertCreateDTO dto = CertDtoMapper.toDto(req, CertUsage.BOTH);

        assertThat(dto.getAlgorithm()).isNull();
        assertThat(dto.getCertUsage()).isEqualTo(CertUsage.BOTH); // 由默认值补
        assertThat(dto.getSignatureAlg()).isNull();
        assertThat(dto.getDigestAlg()).isNull();
        assertThat(dto.getOutputFormats()).containsExactlyInAnyOrder(OutputFormat.values());
    }

    @Test
    void toDto_explicitCertUsage_overridesDefault() {
        CertIssueRequest req = baseRequest();
        req.setCertUsage("sign"); // 大小写不敏感

        CertCreateDTO dto = CertDtoMapper.toDto(req, CertUsage.BOTH);

        assertThat(dto.getCertUsage()).isEqualTo(CertUsage.SIGN);
    }

    @Test
    void toDto_algorithmAndAlgs_passedThrough() {
        CertIssueRequest req = baseRequest();
        req.setAlgorithm("RSA");
        req.setSignatureAlg("SHA256withRSA");
        req.setDigestAlg("SHA-256");

        CertCreateDTO dto = CertDtoMapper.toDto(req, CertUsage.SIGN);

        assertThat(dto.getAlgorithm()).isEqualTo(Algorithm.RSA);
        assertThat(dto.getSignatureAlg()).isEqualTo("SHA256withRSA");
        assertThat(dto.getDigestAlg()).isEqualTo("SHA-256");
    }

    @Test
    void toDto_blankAlgs_normalisedToNull() {
        CertIssueRequest req = baseRequest();
        req.setSignatureAlg("   ");
        req.setDigestAlg("");

        CertCreateDTO dto = CertDtoMapper.toDto(req);

        assertThat(dto.getSignatureAlg()).isNull();
        assertThat(dto.getDigestAlg()).isNull();
    }

    @Test
    void toDto_outputFormats_subsetHonoured() {
        CertIssueRequest req = baseRequest();
        req.setOutputFormats(List.of("PEM", "p12"));

        CertCreateDTO dto = CertDtoMapper.toDto(req);

        assertThat(dto.getOutputFormats()).containsExactlyInAnyOrder(OutputFormat.PEM, OutputFormat.P12);
    }

    @Test
    void toDto_emptyOutputFormatsList_fallsBackToAll() {
        CertIssueRequest req = baseRequest();
        req.setOutputFormats(List.of());

        CertCreateDTO dto = CertDtoMapper.toDto(req);

        assertThat(dto.getOutputFormats()).isEqualTo(EnumSet.allOf(OutputFormat.class));
    }
}
