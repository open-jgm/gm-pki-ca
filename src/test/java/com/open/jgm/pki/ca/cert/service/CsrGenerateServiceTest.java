package com.open.jgm.pki.ca.cert.service;

import com.open.jgm.pki.ca.cert.dto.request.CsrGenerateRequest;
import com.open.jgm.pki.ca.cert.dto.response.CsrParseResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CsrGenerateServiceTest {

    private final CsrGenerateService service = new CsrGenerateService();
    private final CsrParseService parseService = new CsrParseService();

    private static CsrGenerateRequest validRequest() {
        CsrGenerateRequest req = new CsrGenerateRequest();
        req.setDnCn("张三");
        req.setDnC("CN");
        req.setDnSt("DEMO");
        req.setDnL("DEMO");
        req.setDnStreet("road 1");
        req.setDnO("openCA");
        req.setDnOu("dev");
        req.setDnEmail("a@example.com");
        return req;
    }

    @Test
    void generate_returnsCsrAndPrivateKeyPem() {
        CsrGenerateService.GeneratedCsr result = service.generate(validRequest());

        assertThat(new String(result.csrPem(), StandardCharsets.UTF_8))
                .startsWith("-----BEGIN CERTIFICATE REQUEST-----")
                .contains("-----END CERTIFICATE REQUEST-----");
        assertThat(new String(result.privateKeyPem(), StandardCharsets.UTF_8))
                .startsWith("-----BEGIN PRIVATE KEY-----")
                .contains("-----END PRIVATE KEY-----");
    }

    @Test
    void generate_csrCanBeParsedAsSm2() {
        CsrGenerateService.GeneratedCsr result = service.generate(validRequest());
        String csrPem = new String(result.csrPem(), StandardCharsets.UTF_8);

        CsrParseResult parsed = parseService.parse(csrPem);

        assertThat(parsed.getDetectedAlgorithm()).isEqualTo("SM2");
        assertThat(parsed.getCommonName()).isEqualTo("张三");
        assertThat(parsed.getSubjectDn()).contains("C=CN", "ST=DEMO", "L=DEMO", "O=openCA", "OU=dev", "CN=张三");
    }

    @Test
    void generate_nullRequest_throwsCertException() {
        assertThatThrownBy(() -> service.generate(null))
                .isInstanceOf(CertException.class)
                .hasMessageContaining("CSR 生成请求不能为空");
    }
}
