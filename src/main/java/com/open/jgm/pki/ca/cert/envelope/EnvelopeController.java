package com.open.jgm.pki.ca.cert.envelope;

import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import com.github.xiaoymin.knife4j.annotations.ApiSupport;
import com.open.jgm.pki.ca.cert.envelope.dto.EnvelopeDecryptRequest;
import com.open.jgm.pki.ca.cert.envelope.dto.EnvelopeEncryptRequest;
import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.framework.model.Response;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

/**
 * T20：数字信封 REST 接口。
 * <p>
 * 端点：
 * <ul>
 *   <li>POST /api/v2/envelope/encrypt — 用收件人证书加密任意明文</li>
 *   <li>POST /api/v2/envelope/decrypt — 用私钥（+证书）解封</li>
 *   <li>POST /api/v2/envelope/parse   — 解析信封结构与收件人列表（不解密）</li>
 * </ul>
 */
@Api(tags = "数字信封(v2)")
@ApiSupport(order = 20)
@RestController
@RequestMapping("/api/v2/envelope")
@RequiredArgsConstructor
@Slf4j
public class EnvelopeController {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private final EnvelopeService envelopeService;

    @PostMapping("/encrypt")
    @ApiOperationSupport(order = 1)
    @ApiOperation("信封加密（SM2 证书→SM4-CBC；RSA 证书→AES-128-CBC）")
    public Response<String> encrypt(@Valid @RequestBody EnvelopeEncryptRequest req) {
        byte[] plain = Base64.getDecoder().decode(req.getPlainBase64());
        X509Certificate cert = parseCert(req.getRecipientCert());
        byte[] env = envelopeService.encrypt(plain, cert);
        return Response.ok(Base64.getEncoder().encodeToString(env));
    }

    @PostMapping("/decrypt")
    @ApiOperationSupport(order = 2)
    @ApiOperation("信封解密")
    public Response<String> decrypt(@Valid @RequestBody EnvelopeDecryptRequest req) {
        byte[] env = Base64.getDecoder().decode(req.getEnvelopeBase64());

        PrivateKey priv;
        X509Certificate owner = null;

        if (req.getP12Base64() != null && !req.getP12Base64().isBlank()) {
            P12Bundle b = loadP12(req.getP12Base64(), req.getP12Password());
            priv  = b.privateKey;
            owner = b.cert;
        } else if (req.getPrivateKeyPem() != null && !req.getPrivateKeyPem().isBlank()) {
            priv = parsePrivateKeyPem(req.getPrivateKeyPem());
            if (req.getOwnerCertPem() != null && !req.getOwnerCertPem().isBlank()) {
                owner = parseCert(req.getOwnerCertPem());
            }
        } else {
            throw new CertException("必须提供 p12Base64 或 privateKeyPem");
        }

        byte[] plain = envelopeService.decrypt(env, priv, owner);
        return Response.ok(Base64.getEncoder().encodeToString(plain));
    }

    @PostMapping("/parse")
    @ApiOperationSupport(order = 3)
    @ApiOperation("信封解析（不解密）")
    public Response<EnvelopeInfo> parse(@RequestBody String envelopeBase64) {
        if (envelopeBase64 == null || envelopeBase64.isBlank()) {
            throw new CertException("envelopeBase64 不能为空");
        }
        byte[] env = Base64.getDecoder().decode(envelopeBase64.trim());
        return Response.ok(envelopeService.parse(env));
    }

    // ──────────────────────────────────────────────────────────
    // helpers
    // ──────────────────────────────────────────────────────────

    private static X509Certificate parseCert(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new CertException("证书内容不能为空");
        }
        String s = raw.trim();
        try {
            byte[] der;
            if (s.startsWith("-----BEGIN")) {
                der = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            } else {
                der = Base64.getDecoder().decode(s);
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CertException("证书解析失败: " + e.getMessage(), e);
        }
    }

    private static PrivateKey parsePrivateKeyPem(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BC);
            if (obj instanceof PEMKeyPair pkp) {
                return conv.getKeyPair(pkp).getPrivate();
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return conv.getPrivateKey(pki);
            }
            throw new CertException("不支持的私钥 PEM 类型: " + (obj == null ? "null" : obj.getClass().getName()));
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("私钥 PEM 解析失败: " + e.getMessage(), e);
        }
    }

    private static P12Bundle loadP12(String b64, String password) {
        char[] pwd = (password == null ? "" : password).toCharArray();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", BC);
            ks.load(new ByteArrayInputStream(Base64.getDecoder().decode(b64)), pwd);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!ks.isKeyEntry(alias)) continue;
                java.security.Key k = ks.getKey(alias, pwd);
                if (!(k instanceof PrivateKey priv)) continue;
                java.security.cert.Certificate c = ks.getCertificate(alias);
                if (!(c instanceof X509Certificate x509)) continue;
                return new P12Bundle(priv, x509);
            }
            throw new CertException("P12 中未找到私钥+证书对");
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("P12 解析失败: " + e.getMessage(), e);
        }
    }

    private record P12Bundle(PrivateKey privateKey, X509Certificate cert) {}
}
