package com.open.jgm.pki.ca.cert.envelope;

import com.open.jgm.pki.ca.cert.crypto.RSAx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.cert.util.CertDtoMapper;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T21：数字信封 round-trip 测试。
 * <p>
 * 用现有 SM2/RSA maker 在测试中签发用户证书 + 持有私钥，验证 encrypt → parse → decrypt 闭环。
 */
class EnvelopeServiceTest {

    private static final EnvelopeService SERVICE = new EnvelopeService();

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ──────────────────────────────────────────────────────────
    // SM2 信封
    // ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("SM2 信封：加密 → 解析 → 解密 与原文一致")
    void sm2RoundTrip() throws Exception {
        Sm2Pair pair = mintSm2User("ENV-USER-001");
        byte[] plain = "国密信封测试 — Hello 世界 🔐".getBytes(StandardCharsets.UTF_8);

        byte[] envelope = SERVICE.encrypt(plain, pair.cert);
        assertThat(envelope).isNotEmpty();

        EnvelopeInfo info = SERVICE.parse(envelope);
        assertThat(info.getVersion()).isEqualTo(1);
        assertThat(info.getContentEncryptionAlgorithmName()).isEqualTo("SM4-CBC");
        assertThat(info.getIvLength()).isEqualTo(16);
        assertThat(info.getRecipients()).hasSize(1);
        var rv = info.getRecipients().get(0);
        assertThat(rv.getKeyEncryptionAlgorithmName()).isEqualTo("SM2-Encrypt");
        assertThat(rv.getSerialNumberHex()).isEqualTo(pair.cert.getSerialNumber().toString(16));

        byte[] back = SERVICE.decrypt(envelope, pair.keyPair.getPrivate(), pair.cert);
        assertThat(back).isEqualTo(plain);
    }

    @Test
    @DisplayName("SM2 信封：用其它私钥解密失败")
    void sm2WrongKeyFails() throws Exception {
        Sm2Pair sender = mintSm2User("ENV-USER-S");
        Sm2Pair other  = mintSm2User("ENV-USER-O");
        byte[] plain = "hello".getBytes(StandardCharsets.UTF_8);

        byte[] envelope = SERVICE.encrypt(plain, sender.cert);

        // 提供他人证书 → matchRecipient 失败
        assertThatThrownBy(() -> SERVICE.decrypt(envelope, other.keyPair.getPrivate(), other.cert))
                .isInstanceOf(CertException.class);
    }

    // ──────────────────────────────────────────────────────────
    // RSA 信封
    // ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("RSA 信封：AES-128-CBC + RSA-PKCS1 round-trip")
    void rsaRoundTrip() throws Exception {
        RsaPair pair = mintRsaUser("ENV-RSA-001");
        byte[] plain = "RSA-AES envelope test".getBytes(StandardCharsets.UTF_8);

        byte[] envelope = SERVICE.encrypt(plain, pair.cert);

        EnvelopeInfo info = SERVICE.parse(envelope);
        assertThat(info.getContentEncryptionAlgorithmName()).isEqualTo("AES-128-CBC");
        assertThat(info.getRecipients().get(0).getKeyEncryptionAlgorithmName()).isEqualTo("RSA-PKCS1-v1_5");

        byte[] back = SERVICE.decrypt(envelope, pair.keyPair.getPrivate(), pair.cert);
        assertThat(back).isEqualTo(plain);
    }

    // ──────────────────────────────────────────────────────────
    // 错误路径
    // ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("encrypt 明文为空 → CertException")
    void encryptEmptyPlain() {
        assertThatThrownBy(() -> SERVICE.encrypt(null, null))
                .isInstanceOf(CertException.class);
    }

    @Test
    @DisplayName("decrypt 信封字节为空 → CertException")
    void decryptEmptyEnvelope() {
        assertThatThrownBy(() -> SERVICE.decrypt(new byte[0], null, null))
                .isInstanceOf(CertException.class);
    }

    // ──────────────────────────────────────────────────────────
    // 辅助：签发临时用户证书
    // ──────────────────────────────────────────────────────────

    private static Sm2Pair mintSm2User(String cn) throws Exception {
        KeyPair kp = SM2X509CertMaker.softSm2KeyPair();
        CertCreateDTO dto = baseDto(cn);
        CertDescInfo info = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(SM2X509CertMaker.subCACert));
        SM2X509CertMaker maker = new SM2X509CertMaker();
        X509CertificateHolder h = maker.makeUserCertHolder(kp, dto, info);
        X509Certificate cert = SM2CertUtil.convertToX509Certificate(h.getEncoded());
        return new Sm2Pair(kp, cert);
    }

    private static RsaPair mintRsaUser(String cn) throws Exception {
        KeyPair kp = RSAx509CertMaker.generateRsaKeyPair(2048);
        CertCreateDTO dto = baseDto(cn);
        CertDescInfo info = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(RSAx509CertMaker.subCACert));
        RSAx509CertMaker maker = new RSAx509CertMaker();
        X509CertificateHolder h = maker.makeUserCertHolder(kp, dto, info);
        X509Certificate cert = SM2CertUtil.convertToX509Certificate(h.getEncoded());
        return new RsaPair(kp, cert);
    }

    private static CertCreateDTO baseDto(String cn) {
        CertCreateDTO d = new CertCreateDTO();
        d.setDn_cn(cn);
        d.setDn_c("CN");
        d.setDn_st("DEMO");
        d.setDn_l("DEMO");
        d.setDn_o("OPEN-GM-JCA DEMO");
        d.setDn_ou("DEMO CA");
        d.setCertValidMonth(12);
        return d;
    }

    private record Sm2Pair(KeyPair keyPair, X509Certificate cert) {}
    private record RsaPair(KeyPair keyPair, X509Certificate cert) {}
}
