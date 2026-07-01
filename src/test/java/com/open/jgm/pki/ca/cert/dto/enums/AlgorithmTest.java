package com.open.jgm.pki.ca.cert.dto.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AlgorithmTest {

    @Test
    void parseOrNull_blank_returnsNull() {
        assertThat(Algorithm.parseOrNull(null)).isNull();
        assertThat(Algorithm.parseOrNull("")).isNull();
        assertThat(Algorithm.parseOrNull("   ")).isNull();
    }

    @Test
    void parseOrNull_caseInsensitive() {
        assertThat(Algorithm.parseOrNull("sm2")).isEqualTo(Algorithm.SM2);
        assertThat(Algorithm.parseOrNull("Rsa")).isEqualTo(Algorithm.RSA);
        assertThat(Algorithm.parseOrNull("ECC")).isEqualTo(Algorithm.ECC);
    }

    @Test
    void parseOrNull_invalidThrows() {
        assertThatThrownBy(() -> Algorithm.parseOrNull("dsa"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported algorithm");
    }
}
