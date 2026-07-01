package com.open.jgm.pki.ca.cert.util;

import com.open.jgm.pki.ca.cert.crypto.RSAx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T22：v3 扩展项解析测试。
 */
class X509ExtensionParserTest {

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void rsaUserCert_extensionsParsed() throws Exception {
        // 用 RSA maker 签发一张终端实体证书，含 KU/EKU/AKI/SKI
        CertCreateDTO dto = baseDto("EXT-USER-001");
        dto.setKeyUsages(List.of("digitalSignature", "keyEncipherment"));
        dto.setExtendedKeyUsages(List.of("serverAuth", "clientAuth"));
        dto.setSubjectAltNames(List.of("dns:example.com", "ip:192.168.1.1"));

        KeyPair kp = RSAx509CertMaker.generateRsaKeyPair(2048);
        CertDescInfo subCaInfo = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(RSAx509CertMaker.subCACert));
        X509CertificateHolder h = new RSAx509CertMaker().makeUserCertHolder(kp, dto, subCaInfo);
        X509Certificate cert = SM2CertUtil.convertToX509Certificate(h.getEncoded());

        var v = X509ExtensionParser.parse(cert);

        assertThat(v.getKeyUsages()).containsExactlyInAnyOrder("digitalSignature", "keyEncipherment");
        assertThat(v.getExtendedKeyUsages()).contains("serverAuth", "clientAuth");
        assertThat(v.getSubjectAltNames()).contains("dns:example.com", "ip:192.168.1.1");
        assertThat(v.getSubjectKeyIdentifierHex()).isNotBlank();
        assertThat(v.getAuthorityKeyIdentifierHex()).isNotBlank();
        assertThat(v.getBasicConstraintsCA()).isFalse();
    }

    private static CertCreateDTO baseDto(String cn) {
        CertCreateDTO d = new CertCreateDTO();
        d.setDn_cn(cn);
        d.setDn_c("CN");
        d.setDn_o("test");
        d.setDn_ou("test");
        d.setCertValidMonth(6);
        return d;
    }
}
