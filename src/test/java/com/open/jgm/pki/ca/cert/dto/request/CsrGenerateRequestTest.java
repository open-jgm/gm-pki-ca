package com.open.jgm.pki.ca.cert.dto.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CsrGenerateRequestTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    private final ObjectMapper mapper = new ObjectMapper();

    private static CsrGenerateRequest valid() {
        CsrGenerateRequest req = new CsrGenerateRequest();
        req.setDnCn("张三");
        req.setDnC("CN");
        req.setDnSt("DEMO");
        req.setDnL("DEMO");
        req.setDnO("openCA");
        req.setDnOu("dev");
        return req;
    }

    @Test
    void validRequest_passesValidation() {
        Set<ConstraintViolation<CsrGenerateRequest>> violations = validator.validate(valid());
        assertThat(violations).isEmpty();
    }

    @Test
    void blankRequiredFields_fail() {
        CsrGenerateRequest req = valid();
        req.setDnCn("");
        req.setDnC("");
        req.setDnO("");
        req.setDnOu("");

        Set<ConstraintViolation<CsrGenerateRequest>> violations = validator.validate(req);

        assertThat(violations).extracting(ConstraintViolation::getMessage)
                .contains("DN_CN 不能为空", "DN_C 不能为空", "DN_O 不能为空", "DN_OU 不能为空");
    }

    @Test
    void invalidEmail_fails() {
        CsrGenerateRequest req = valid();
        req.setDnEmail("bad-email");

        Set<ConstraintViolation<CsrGenerateRequest>> violations = validator.validate(req);

        assertThat(violations).extracting(ConstraintViolation::getMessage)
                .contains("邮箱格式不正确");
    }

    @Test
    void jsonAlias_underscoreFieldsAccepted() throws Exception {
        String json = """
                {
                  "dn_cn": "张三",
                  "dn_c": "CN",
                  "dn_st": "DEMO",
                  "dn_l": "DEMO",
                  "dn_street": "road 1",
                  "dn_o": "openCA",
                  "dn_ou": "dev",
                  "dn_email": "a@example.com"
                }
                """;

        CsrGenerateRequest req = mapper.readValue(json, CsrGenerateRequest.class);

        assertThat(req.getDnCn()).isEqualTo("张三");
        assertThat(req.getDnC()).isEqualTo("CN");
        assertThat(req.getDnSt()).isEqualTo("DEMO");
        assertThat(req.getDnL()).isEqualTo("DEMO");
        assertThat(req.getDnStreet()).isEqualTo("road 1");
        assertThat(req.getDnO()).isEqualTo("openCA");
        assertThat(req.getDnOu()).isEqualTo("dev");
        assertThat(req.getDnEmail()).isEqualTo("a@example.com");
    }
}
