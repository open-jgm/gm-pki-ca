package com.open.jgm.pki.ca.cert.inspect;

import com.open.jgm.pki.ca.cert.crypto.RSAx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.inspect.dto.KeyInspectRequest;
import com.open.jgm.pki.ca.cert.inspect.dto.KeyInspectResult;
import com.open.jgm.pki.ca.cert.util.CertDtoMapper;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T24：私钥检查 + 私钥/证书匹配测试。
 */
class KeyInspectServiceTest {

    private static final KeyInspectService SERVICE = new KeyInspectService();

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("RSA 私钥与对应证书匹配 → match=true")
    void rsaMatch() throws Exception {
        KeyPair kp = RSAx509CertMaker.generateRsaKeyPair(2048);
        X509Certificate cert = mintRsaCert(kp, "KEY-MATCH-RSA");

        KeyInspectRequest req = new KeyInspectRequest();
        req.setPrivateKeyPem(toPriPem(kp));
        req.setCertPemOrBase64(Base64.getEncoder().encodeToString(cert.getEncoded()));

        KeyInspectResult r = SERVICE.inspect(req);
        assertThat(r.getAlgorithm()).isEqualTo("RSA");
        assertThat(r.getBits()).isEqualTo(2048);
        assertThat(r.getMatchCertificate()).isTrue();
        assertThat(r.getMismatchReason()).isNull();
    }

    @Test
    @DisplayName("RSA 私钥与他人证书不匹配 → match=false + 原因")
    void rsaMismatch() throws Exception {
        KeyPair a = RSAx509CertMaker.generateRsaKeyPair(2048);
        KeyPair b = RSAx509CertMaker.generateRsaKeyPair(2048);
        X509Certificate certB = mintRsaCert(b, "KEY-MISMATCH-RSA");

        KeyInspectRequest req = new KeyInspectRequest();
        req.setPrivateKeyPem(toPriPem(a));
        req.setCertPemOrBase64(Base64.getEncoder().encodeToString(certB.getEncoded()));

        KeyInspectResult r = SERVICE.inspect(req);
        assertThat(r.getMatchCertificate()).isFalse();
        assertThat(r.getMismatchReason()).contains("模数不一致");
    }

    @Test
    @DisplayName("SM2 私钥（EC + sm2p256v1 曲线）正确识别")
    void sm2Detected() throws Exception {
        KeyPair kp = SM2X509CertMaker.softSm2KeyPair();

        KeyInspectRequest req = new KeyInspectRequest();
        req.setPrivateKeyPem(toPriPem(kp));

        KeyInspectResult r = SERVICE.inspect(req);
        assertThat(r.getAlgorithm()).isEqualTo("SM2-EC");
        assertThat(r.getCurve()).isNotBlank();
        assertThat(r.getMatchCertificate()).isNull();
    }

    // ──────────────────────────────────────────────────────────

    private static X509Certificate mintRsaCert(KeyPair kp, String cn) throws Exception {
        CertCreateDTO dto = new CertCreateDTO();
        dto.setDn_cn(cn);
        dto.setDn_c("CN");
        dto.setDn_o("test");
        dto.setDn_ou("test");
        dto.setCertValidMonth(6);
        CertDescInfo info = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(RSAx509CertMaker.subCACert));
        X509CertificateHolder h = new RSAx509CertMaker().makeUserCertHolder(kp, dto, info);
        return SM2CertUtil.convertToX509Certificate(h.getEncoded());
    }

    private static String toPriPem(KeyPair kp) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            w.writeObject(new PemObject("PRIVATE KEY", kp.getPrivate().getEncoded()));
        }
        return sw.toString();
    }
}
