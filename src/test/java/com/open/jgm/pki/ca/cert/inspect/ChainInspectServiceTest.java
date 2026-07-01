package com.open.jgm.pki.ca.cert.inspect;

import cn.hutool.core.codec.Base64;
import com.open.jgm.pki.ca.cert.crypto.RSAx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.inspect.dto.ChainInspectRequest;
import com.open.jgm.pki.ca.cert.inspect.dto.ChainInspectResult;
import com.open.jgm.pki.ca.cert.util.CertDtoMapper;
import com.open.jgm.pki.ca.cert.util.CertParseUtil;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T25：证书链信任路径验证测试。
 */
class ChainInspectServiceTest {

    private static final ChainInspectService SERVICE = new ChainInspectService();

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("RSA 链 ee→subCA→rootCA + anchors=[rootCA] → trusted=true")
    void rsaChainTrusted() throws Exception {
        X509Certificate ee = mintRsaUser("CHAIN-EE-001");
        String subCa = RSAx509CertMaker.subCACert;
        String rootCa = RSAx509CertMaker.rootCACert;

        ChainInspectRequest req = new ChainInspectRequest();
        req.setChain(List.of(Base64.encode(ee.getEncoded()), subCa, rootCa));
        req.setTrustAnchors(List.of(rootCa));

        ChainInspectResult r = SERVICE.inspect(req);
        assertThat(r.getTrusted()).isTrue();
        assertThat(r.getBrokenAtIndex()).isNull();
        assertThat(r.getNodes()).hasSize(3);
        assertThat(r.getNodes().get(0).getSignatureVerified()).isTrue();
    }

    @Test
    @DisplayName("链中相邻 issuer/subject 不匹配 → trusted=false + brokenAtIndex")
    void chainBroken() throws Exception {
        X509Certificate ee = mintRsaUser("CHAIN-BROKEN");
        // 故意把 rootCA 当作 issuer 给 ee（跳过 subCa）
        String rootCa = RSAx509CertMaker.rootCACert;

        ChainInspectRequest req = new ChainInspectRequest();
        req.setChain(List.of(Base64.encode(ee.getEncoded()), rootCa));

        ChainInspectResult r = SERVICE.inspect(req);
        assertThat(r.getTrusted()).isFalse();
        assertThat(r.getBrokenAtIndex()).isEqualTo(0);
        assertThat(r.getReason()).contains("不匹配");
    }

    // ──────────────────────────────────────────────────────────

    private static X509Certificate mintRsaUser(String cn) throws Exception {
        KeyPair kp = RSAx509CertMaker.generateRsaKeyPair(2048);
        CertCreateDTO dto = new CertCreateDTO();
        dto.setDn_cn(cn);
        dto.setDn_c("CN");
        dto.setDn_o("test");
        dto.setDn_ou("test");
        dto.setCertValidMonth(12);
        CertDescInfo info = CertDtoMapper.toLegacyDescInfo(CertParseUtil.parse(RSAx509CertMaker.subCACert));
        X509CertificateHolder h = new RSAx509CertMaker().makeUserCertHolder(kp, dto, info);
        return SM2CertUtil.convertToX509Certificate(h.getEncoded());
    }
}
