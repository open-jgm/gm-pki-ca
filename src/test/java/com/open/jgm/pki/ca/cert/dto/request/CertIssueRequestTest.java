package com.open.jgm.pki.ca.cert.dto.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.enums.CertUsage;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CertIssueRequest 的 Bean Validation 与解析辅助方法测试。
 */
class CertIssueRequestTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    private final ObjectMapper mapper = new ObjectMapper();

    private static CertIssueRequest valid() {
        CertIssueRequest req = new CertIssueRequest();
        req.setDnCn("张三");
        req.setDnC("CN");
        req.setDnO("openCA");
        req.setDnOu("dev");
        req.setCertValidMonth(12);
        return req;
    }

    @Test
    void validRequest_passesValidation() {
        Set<ConstraintViolation<CertIssueRequest>> violations = validator.validate(valid());
        assertThat(violations).isEmpty();
    }

    @Test
    void blankCn_fails() {
        CertIssueRequest req = valid();
        req.setDnCn("");
        Set<ConstraintViolation<CertIssueRequest>> violations = validator.validate(req);
        assertThat(violations).extracting(ConstraintViolation::getMessage)
                .contains("DN_CN 不能为空");
    }

    @Test
    void invalidCertValidMonth_fails() {
        CertIssueRequest req = valid();
        req.setCertValidMonth(0);
        assertThat(validator.validate(req)).isNotEmpty();

        req.setCertValidMonth(361);
        assertThat(validator.validate(req)).isNotEmpty();
    }

    @Test
    void resolveCertUsage_lowercase() {
        CertIssueRequest req = valid();
        req.setCertUsage("both");
        assertThat(req.resolveCertUsage()).isEqualTo(CertUsage.BOTH);
    }

    @Test
    void resolveAlgorithm_lowercase() {
        CertIssueRequest req = valid();
        req.setAlgorithm("sm2");
        assertThat(req.resolveAlgorithm()).isEqualTo(Algorithm.SM2);
    }

    @Test
    void resolveOutputFormats_unspecified_returnsAll() {
        CertIssueRequest req = valid();
        assertThat(req.resolveOutputFormats()).containsExactlyInAnyOrder(OutputFormat.values());
    }

    @Test
    void jsonAlias_underscoreFieldsAccepted() throws Exception {
        // 兼容下划线 + 新字段别名
        String json = """
                {
                  "dn_cn": "张三",
                  "dn_c": "CN",
                  "dn_o": "openCA",
                  "dn_ou": "dev",
                  "certValidMonth": 24,
                  "cert_usage": "SIGN",
                  "signature_alg": "SHA256withRSA",
                  "digest_alg": "SHA-256",
                  "output_formats": ["PEM","DER"]
                }
                """;
        CertIssueRequest req = mapper.readValue(json, CertIssueRequest.class);

        assertThat(req.getDnCn()).isEqualTo("张三");
        assertThat(req.getCertUsage()).isEqualTo("SIGN");
        assertThat(req.getSignatureAlg()).isEqualTo("SHA256withRSA");
        assertThat(req.getDigestAlg()).isEqualTo("SHA-256");
        assertThat(req.getOutputFormats()).containsExactly("PEM", "DER");
    }
}
