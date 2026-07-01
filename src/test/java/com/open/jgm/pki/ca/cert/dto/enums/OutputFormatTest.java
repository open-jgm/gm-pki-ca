package com.open.jgm.pki.ca.cert.dto.enums;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OutputFormatTest {

    @Test
    void parseOrAll_null_returnsAll() {
        Set<OutputFormat> result = OutputFormat.parseOrAll(null);
        assertThat(result).containsExactlyInAnyOrder(OutputFormat.values());
    }

    @Test
    void parseOrAll_empty_returnsAll() {
        assertThat(OutputFormat.parseOrAll(List.of())).isEqualTo(EnumSet.allOf(OutputFormat.class));
    }

    @Test
    void parseOrAll_caseInsensitive() {
        Set<OutputFormat> result = OutputFormat.parseOrAll(List.of("pem", "P12"));
        assertThat(result).containsExactlyInAnyOrder(OutputFormat.PEM, OutputFormat.P12);
    }

    @Test
    void parseOrAll_blankEntriesIgnored() {
        Set<OutputFormat> result = OutputFormat.parseOrAll(List.of("", " ", "der"));
        assertThat(result).containsExactly(OutputFormat.DER);
    }

    @Test
    void parseOrAll_invalidThrows() {
        assertThatThrownBy(() -> OutputFormat.parseOrAll(List.of("xml")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported outputFormat");
    }
}
