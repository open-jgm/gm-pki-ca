package com.open.jgm.pki.ca.cert.service;

import com.open.jgm.pki.ca.cert.crypto.SM2CertUtil;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.dto.response.CsrParseResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * T05：CSR 解析服务，支持 SM2 / RSA / ECC PKCS#10。
 * <p>
 * 接受 base64(DER) 或 PEM 两种输入；提取 Subject / 公钥参数 / 已请求扩展，并按算法给出推荐扩展。
 */
@Service
@Slf4j
public class CsrParseService {

    /** EC named curves -> friendly name for response */
    private static final ASN1ObjectIdentifier OID_EC_PUBLIC_KEY = X9ObjectIdentifiers.id_ecPublicKey;
    private static final ASN1ObjectIdentifier OID_RSA          = PKCSObjectIdentifiers.rsaEncryption;
    private static final ASN1ObjectIdentifier OID_SM2_CURVE    = GMObjectIdentifiers.sm2p256v1;

    public CsrParseResult parse(String input) {
        try {
            PKCS10CertificationRequest csr = readCsr(input);
            SubjectPublicKeyInfo spki     = csr.getSubjectPublicKeyInfo();
            Algorithm algo                = detectAlgorithm(spki);

            String subjectDn   = csr.getSubject().toString();
            String commonName  = SM2CertUtil.getUniversalName(csr.getSubject());
            String pubAlgName  = friendlyAlgName(spki, algo);
            String pubKeyParam = describePublicKeyParam(spki, algo);
            String pubKeyPem   = toPublicKeyPem(spki);
            String sigAlg      = csr.getSignatureAlgorithm().getAlgorithm().getId();

            // 已请求扩展（CSR 的 extensionRequest 属性）
            Extensions requested = extractExtensionRequest(csr);
            List<String> reqKu   = readKeyUsages(requested);
            List<String> reqEku  = readExtendedKeyUsages(requested);
            List<String> reqSan  = readSubjectAltNames(requested);
            Boolean reqCa        = readBasicConstraintsCA(requested);

            // 推荐扩展（按算法）
            List<String> recKu   = recommendedKeyUsages(algo);
            List<String> recEku  = recommendedEku(algo);

            return CsrParseResult.builder()
                    .detectedAlgorithm(algo.name())
                    .subjectDn(subjectDn)
                    .commonName(commonName)
                    .publicKeyAlgorithm(pubAlgName)
                    .publicKeyParam(pubKeyParam)
                    .publicKeyPem(pubKeyPem)
                    .signatureAlgorithm(sigAlg)
                    .requestedKeyUsages(reqKu)
                    .requestedExtendedKeyUsages(reqEku)
                    .requestedSubjectAltNames(reqSan)
                    .requestedBasicConstraintsCA(reqCa)
                    .recommendedKeyUsages(recKu)
                    .recommendedExtendedKeyUsages(recEku)
                    .build();
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("CSR 解析失败", e);
            throw new CertException("CSR 解析失败：" + e.getMessage(), e);
        }
    }

    // ── input ────────────────────────────────────────────

    public PKCS10CertificationRequest readCsr(String input) throws Exception {
        if (input == null || input.isBlank()) {
            throw new CertException("CSR 内容不能为空");
        }
        String trimmed = input.trim();
        if (trimmed.startsWith("-----BEGIN")) {
            try (PEMParser parser = new PEMParser(new StringReader(trimmed))) {
                Object obj = parser.readObject();
                if (!(obj instanceof PKCS10CertificationRequest csr)) {
                    throw new CertException("不是合法的 PKCS#10 CSR");
                }
                return csr;
            }
        }
        // 尝试 base64 DER
        byte[] der = Base64.getDecoder().decode(stripWhitespace(trimmed));
        return new PKCS10CertificationRequest(der);
    }

    private static String stripWhitespace(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isWhitespace(c)) sb.append(c);
        }
        return sb.toString();
    }

    // ── algorithm detection ──────────────────────────────

    private static Algorithm detectAlgorithm(SubjectPublicKeyInfo spki) {
        ASN1ObjectIdentifier algOid = spki.getAlgorithm().getAlgorithm();
        if (OID_RSA.equals(algOid)) {
            return Algorithm.RSA;
        }
        if (OID_EC_PUBLIC_KEY.equals(algOid)) {
            ASN1Encodable params = spki.getAlgorithm().getParameters();
            if (params instanceof ASN1ObjectIdentifier curveOid && OID_SM2_CURVE.equals(curveOid)) {
                return Algorithm.SM2;
            }
            return Algorithm.ECC;
        }
        throw new CertException("不支持的公钥算法 OID: " + algOid);
    }

    private static String friendlyAlgName(SubjectPublicKeyInfo spki, Algorithm algo) {
        return switch (algo) {
            case RSA -> "RSA";
            case SM2 -> "SM2 (id-ecPublicKey + sm2p256v1)";
            case ECC -> "EC (" + describeCurve(spki) + ")";
        };
    }

    private static String describePublicKeyParam(SubjectPublicKeyInfo spki, Algorithm algo) {
        return switch (algo) {
            case RSA -> {
                try {
                    var rsa = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(spki.parsePublicKey());
                    yield rsa.getModulus().bitLength() + " bit";
                } catch (Exception e) {
                    yield "RSA";
                }
            }
            case SM2 -> "sm2p256v1";
            case ECC -> describeCurve(spki);
        };
    }

    private static String describeCurve(SubjectPublicKeyInfo spki) {
        ASN1Encodable params = spki.getAlgorithm().getParameters();
        if (params instanceof ASN1ObjectIdentifier oid) {
            if (X9ObjectIdentifiers.prime256v1.equals(oid)) return "prime256v1";
            if (SECObjectIdentifiers.secp256r1.equals(oid)) return "prime256v1";
            return oid.getId();
        }
        return "unknown";
    }

    // ── PEM output ───────────────────────────────────────

    private static String toPublicKeyPem(SubjectPublicKeyInfo spki) {
        try (StringWriter sw = new StringWriter();
             PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject("PUBLIC KEY", spki.getEncoded()));
            pw.flush();
            return sw.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // ── extension extraction ─────────────────────────────

    private static Extensions extractExtensionRequest(PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs == null || attrs.length == 0) return null;
        ASN1Encodable[] values = attrs[0].getAttributeValues();
        if (values == null || values.length == 0) return null;
        return Extensions.getInstance(values[0]);
    }

    private static List<String> readKeyUsages(Extensions ext) {
        if (ext == null) return List.of();
        Extension e = ext.getExtension(Extension.keyUsage);
        if (e == null) return List.of();
        try {
            KeyUsage ku = KeyUsage.getInstance(e.getParsedValue());
            // KeyUsage 内部位顺序按 RFC 5280
            List<String> names = new ArrayList<>();
            if (ku.hasUsages(KeyUsage.digitalSignature)) names.add("digitalSignature");
            if (ku.hasUsages(KeyUsage.nonRepudiation))   names.add("nonRepudiation");
            if (ku.hasUsages(KeyUsage.keyEncipherment))  names.add("keyEncipherment");
            if (ku.hasUsages(KeyUsage.dataEncipherment)) names.add("dataEncipherment");
            if (ku.hasUsages(KeyUsage.keyAgreement))     names.add("keyAgreement");
            if (ku.hasUsages(KeyUsage.keyCertSign))      names.add("keyCertSign");
            if (ku.hasUsages(KeyUsage.cRLSign))          names.add("cRLSign");
            if (ku.hasUsages(KeyUsage.encipherOnly))     names.add("encipherOnly");
            if (ku.hasUsages(KeyUsage.decipherOnly))     names.add("decipherOnly");
            return names;
        } catch (Exception ex) {
            return List.of();
        }
    }

    private static List<String> readExtendedKeyUsages(Extensions ext) {
        if (ext == null) return List.of();
        Extension e = ext.getExtension(Extension.extendedKeyUsage);
        if (e == null) return List.of();
        try {
            org.bouncycastle.asn1.x509.ExtendedKeyUsage eku =
                    org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(e.getParsedValue());
            List<String> names = new ArrayList<>();
            for (KeyPurposeId kp : eku.getUsages()) {
                names.add(friendlyEku(kp));
            }
            return names;
        } catch (Exception ex) {
            return List.of();
        }
    }

    private static String friendlyEku(KeyPurposeId kp) {
        if (KeyPurposeId.id_kp_serverAuth.equals(kp))      return "serverAuth";
        if (KeyPurposeId.id_kp_clientAuth.equals(kp))      return "clientAuth";
        if (KeyPurposeId.id_kp_codeSigning.equals(kp))     return "codeSigning";
        if (KeyPurposeId.id_kp_emailProtection.equals(kp)) return "emailProtection";
        if (KeyPurposeId.id_kp_timeStamping.equals(kp))    return "timeStamping";
        if (KeyPurposeId.id_kp_OCSPSigning.equals(kp))     return "ocspSigning";
        return kp.toOID().getId();
    }

    private static List<String> readSubjectAltNames(Extensions ext) {
        if (ext == null) return List.of();
        Extension e = ext.getExtension(Extension.subjectAlternativeName);
        if (e == null) return List.of();
        try {
            GeneralNames gns = GeneralNames.getInstance(e.getParsedValue());
            List<String> out = new ArrayList<>();
            for (GeneralName gn : gns.getNames()) {
                String type = switch (gn.getTagNo()) {
                    case GeneralName.dNSName                   -> "dns";
                    case GeneralName.iPAddress                 -> "ip";
                    case GeneralName.rfc822Name                -> "email";
                    case GeneralName.uniformResourceIdentifier -> "uri";
                    case GeneralName.directoryName             -> "dirname";
                    default -> "tag" + gn.getTagNo();
                };
                out.add(type + ":" + gn.getName().toString());
            }
            return out;
        } catch (Exception ex) {
            return List.of();
        }
    }

    private static Boolean readBasicConstraintsCA(Extensions ext) {
        if (ext == null) return null;
        Extension e = ext.getExtension(Extension.basicConstraints);
        if (e == null) return null;
        try {
            BasicConstraints bc = BasicConstraints.getInstance(e.getParsedValue());
            return bc.isCA();
        } catch (Exception ex) {
            return null;
        }
    }

    // ── recommendations ──────────────────────────────────

    private static List<String> recommendedKeyUsages(Algorithm algo) {
        return switch (algo) {
            case SM2 -> List.of("digitalSignature", "keyEncipherment");
            case RSA -> List.of("digitalSignature", "keyEncipherment");
            case ECC -> List.of("digitalSignature", "keyAgreement");
        };
    }

    private static List<String> recommendedEku(Algorithm algo) {
        return Arrays.asList("clientAuth", "serverAuth");
    }
}
