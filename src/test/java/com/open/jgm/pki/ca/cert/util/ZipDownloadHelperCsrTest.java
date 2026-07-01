package com.open.jgm.pki.ca.cert.util;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class ZipDownloadHelperCsrTest {

    @Test
    void writeCsrZip_writesBinaryAttachment() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        ZipDownloadHelper.writeCsrZip(
                response,
                "张三",
                "test.csr.pem".getBytes(StandardCharsets.UTF_8),
                "test.key.pem".getBytes(StandardCharsets.UTF_8));

        assertThat(response.getContentType()).isEqualTo("application/octet-stream");
        assertThat(response.getHeader("Content-Disposition")).contains("attachment;filename=");
        assertThat(response.getContentAsByteArray()).isNotEmpty();
    }
}
