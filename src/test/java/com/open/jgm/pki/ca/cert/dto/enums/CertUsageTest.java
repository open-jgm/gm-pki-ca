package com.open.jgm.pki.ca.cert.dto.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertUsageTest {

    @Test
    void parseOrNull_blank_returnsNull() {
        assertThat(CertUsage.parseOrNull(null)).isNull();
        assertThat(CertUsage.parseOrNull("")).isNull();
        assertThat(CertUsage.parseOrNull("   ")).isNull();
    }

    @Test
    void parseOrNull_caseInsensitive() {
        assertThat(CertUsage.parseOrNull("sign")).isEqualTo(CertUsage.SIGN);
        assertThat(CertUsage.parseOrNull("Both")).isEqualTo(CertUsage.BOTH);
    }

    @Test
    void parseOrNull_invalidThrows() {
        assertThatThrownBy(() -> CertUsage.parseOrNull("hybrid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported certUsage");
    }

    @Test
    void needsSignAndNeedsEnc() {
        assertThat(CertUsage.SIGN.needsSign()).isTrue();
        assertThat(CertUsage.SIGN.needsEnc()).isFalse();
        assertThat(CertUsage.ENC.needsSign()).isFalse();
        assertThat(CertUsage.ENC.needsEnc()).isTrue();
        assertThat(CertUsage.BOTH.needsSign()).isTrue();
        assertThat(CertUsage.BOTH.needsEnc()).isTrue();
    }
}
