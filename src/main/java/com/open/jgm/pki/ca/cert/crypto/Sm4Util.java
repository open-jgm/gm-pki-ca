package com.open.jgm.pki.ca.cert.crypto;

import com.open.jgm.pki.ca.cert.exception.CertException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * T16：SM4 对称加密工具（CBC + PKCS7Padding，IV 随机）。
 * <p>
 * 输出格式 {@code IV(16) || CIPHERTEXT}，方便单一字节流持久化与传输；
 * 与 {@code openssl enc -sm4-cbc -K ... -iv ...} 互操作时需要把 IV 单独拆出。
 * <p>
 * 注意：SM4 块长度固定为 16 字节（128 bit），密钥长度也是 16 字节。
 */
public final class Sm4Util {

    private static final String ALGO          = "SM4";
    private static final String TRANSFORMATION = "SM4/CBC/PKCS7Padding";
    private static final String PROVIDER      = BouncyCastleProvider.PROVIDER_NAME;

    /** SM4 块长度 / IV 长度 = 16 字节。 */
    public static final int BLOCK_SIZE = 16;

    /** SM4 标准密钥长度 = 16 字节 = 128 bit。 */
    public static final int KEY_SIZE   = 16;

    private Sm4Util() {}

    // ──────────────────────────────────────────────────────────
    // 密钥生成
    // ──────────────────────────────────────────────────────────

    /** 生成 128-bit 随机 SM4 密钥（16 字节）。 */
    public static byte[] generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGO, PROVIDER);
            kg.init(KEY_SIZE * 8, new SecureRandom());
            SecretKey sk = kg.generateKey();
            return sk.getEncoded();
        } catch (Exception e) {
            throw new CertException("SM4 密钥生成失败", e);
        }
    }

    /** 生成 16 字节随机 IV。 */
    public static byte[] generateIv() {
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // ──────────────────────────────────────────────────────────
    // 加密 / 解密：内嵌 IV
    // ──────────────────────────────────────────────────────────

    /**
     * SM4 加密，输出 {@code IV(16) || CIPHERTEXT}。
     */
    public static byte[] encrypt(byte[] key, byte[] plain) {
        validateKey(key);
        byte[] iv = generateIv();
        byte[] ct = doCipher(Cipher.ENCRYPT_MODE, key, iv, plain);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    /**
     * SM4 解密 {@code IV(16) || CIPHERTEXT}。
     */
    public static byte[] decrypt(byte[] key, byte[] ivPlusCipher) {
        validateKey(key);
        if (ivPlusCipher == null || ivPlusCipher.length < BLOCK_SIZE + BLOCK_SIZE) {
            throw new CertException("SM4 密文长度不足");
        }
        byte[] iv = Arrays.copyOfRange(ivPlusCipher, 0, BLOCK_SIZE);
        byte[] ct = Arrays.copyOfRange(ivPlusCipher, BLOCK_SIZE, ivPlusCipher.length);
        return doCipher(Cipher.DECRYPT_MODE, key, iv, ct);
    }

    // ──────────────────────────────────────────────────────────
    // 加密 / 解密：外置 IV（用于 PKCS7 信封 — IV 单独 ASN.1 字段承载）
    // ──────────────────────────────────────────────────────────

    public static byte[] encryptWithIv(byte[] key, byte[] iv, byte[] plain) {
        validateKey(key);
        validateIv(iv);
        return doCipher(Cipher.ENCRYPT_MODE, key, iv, plain);
    }

    public static byte[] decryptWithIv(byte[] key, byte[] iv, byte[] cipher) {
        validateKey(key);
        validateIv(iv);
        return doCipher(Cipher.DECRYPT_MODE, key, iv, cipher);
    }

    // ──────────────────────────────────────────────────────────
    // 内部
    // ──────────────────────────────────────────────────────────

    private static byte[] doCipher(int mode, byte[] key, byte[] iv, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
            cipher.init(mode, new SecretKeySpec(key, ALGO), new IvParameterSpec(iv));
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new CertException("SM4 " + (mode == Cipher.ENCRYPT_MODE ? "加密" : "解密") + "失败: " + e.getMessage(), e);
        }
    }

    private static void validateKey(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new CertException("SM4 密钥长度必须为 " + KEY_SIZE + " 字节，实际 "
                    + (key == null ? "null" : String.valueOf(key.length)));
        }
    }

    private static void validateIv(byte[] iv) {
        if (iv == null || iv.length != BLOCK_SIZE) {
            throw new CertException("SM4 IV 长度必须为 " + BLOCK_SIZE + " 字节，实际 "
                    + (iv == null ? "null" : String.valueOf(iv.length)));
        }
    }
}
