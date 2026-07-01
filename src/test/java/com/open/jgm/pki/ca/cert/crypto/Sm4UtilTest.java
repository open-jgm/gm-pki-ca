package com.open.jgm.pki.ca.cert.crypto;

import com.open.jgm.pki.ca.cert.exception.CertException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T16：SM4 工具单测。
 */
class Sm4UtilTest {

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void generateKey_lengthIsSixteen() {
        byte[] k = Sm4Util.generateKey();
        assertThat(k).hasSize(Sm4Util.KEY_SIZE);
    }

    @Test
    void generateIv_lengthIsSixteenAndRandom() {
        byte[] a = Sm4Util.generateIv();
        byte[] b = Sm4Util.generateIv();
        assertThat(a).hasSize(Sm4Util.BLOCK_SIZE);
        assertThat(b).hasSize(Sm4Util.BLOCK_SIZE);
        assertThat(Arrays.equals(a, b)).isFalse();
    }

    @Test
    void encryptThenDecrypt_inlineIv_roundTrip() {
        byte[] key = Sm4Util.generateKey();
        byte[] plain = "国密 SM4 round-trip 测试 🔐".getBytes(StandardCharsets.UTF_8);
        byte[] ct = Sm4Util.encrypt(key, plain);
        byte[] back = Sm4Util.decrypt(key, ct);
        assertThat(back).isEqualTo(plain);
        // 输出至少包含 IV(16) + 至少一个块 16
        assertThat(ct.length).isGreaterThanOrEqualTo(Sm4Util.BLOCK_SIZE + Sm4Util.BLOCK_SIZE);
    }

    @Test
    void encryptThenDecrypt_externalIv_roundTrip() {
        byte[] key = Sm4Util.generateKey();
        byte[] iv  = Sm4Util.generateIv();
        byte[] plain = "abc".getBytes(StandardCharsets.UTF_8);
        byte[] ct = Sm4Util.encryptWithIv(key, iv, plain);
        byte[] back = Sm4Util.decryptWithIv(key, iv, ct);
        assertThat(back).isEqualTo(plain);
    }

    @Test
    void encrypt_wrongKeyLength_throws() {
        byte[] badKey = new byte[8];
        assertThatThrownBy(() -> Sm4Util.encrypt(badKey, new byte[]{1, 2, 3}))
                .isInstanceOf(CertException.class)
                .hasMessageContaining("密钥长度");
    }

    @Test
    void decrypt_truncatedInput_throws() {
        byte[] key = Sm4Util.generateKey();
        assertThatThrownBy(() -> Sm4Util.decrypt(key, new byte[5]))
                .isInstanceOf(CertException.class)
                .hasMessageContaining("长度不足");
    }
}
