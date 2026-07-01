package com.open.jgm.pki.ca.cert.crypto;

import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.util.CertExtensionResolver;
import cn.hutool.core.codec.Base64;
import com.open.jgm.pki.ca.framework.exception.BusinessException;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.lang.Snowflake;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.IdUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.*;
import java.util.*;

@Slf4j
public class SM2X509CertMaker {

    private static enum CertLevel {
        RootCA, SubCA, EndEntity
    } // class CertLevel

    static Snowflake snowflake = IdUtil.createSnowflake(1L, 1L);
    static BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bcProvider);
    }

    public static final String SIGN_ALGO_SM3WITHSM2 = "SM3withSM2";
    public static final String PASSWORD = "12345678";
    static final String rootPub = "3059301306072a8648ce3d020106082a811ccf5501822d0342000415c03209d3a389034d5a25848f1e39752e3f5e77cc2f7db64d4a99bc00aa18979ac7af96dd8be657a622ad9094fa67b73e89f006a2390d764a787b11ae38dd3b";
    static final String rootPri = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042059112852fdbe9a0171d2219f3af40eca3ee5fe6e2826f41c85b1d71ad664a87fa00a06082a811ccf5501822da1440342000415c03209d3a389034d5a25848f1e39752e3f5e77cc2f7db64d4a99bc00aa18979ac7af96dd8be657a622ad9094fa67b73e89f006a2390d764a787b11ae38dd3b";
    public static final String issuerPublicKeyBase64 = "3059301306072a8648ce3d020106082a811ccf5501822d034200047da837b42bf17a4e1e9f0516bed5bf7398e9898dd6147c5191be1f989c9528187b3677b93cefe1a1ec6146f1e5f43dec94e4aea818f95061db2792adb12cbc09";
    public static final String issuerPrivateKeyBase64 = "308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104202bccd2fb2f1bd3da16785d54dfb126083d1ea7fa56e20b1050e3d4f5257cc137a00a06082a811ccf5501822da144034200047da837b42bf17a4e1e9f0516bed5bf7398e9898dd6147c5191be1f989c9528187b3677b93cefe1a1ec6146f1e5f43dec94e4aea818f95061db2792adb12cbc09";
    public static final String rootCACert = "MIICUjCCAfigAwIBAgIIGXLSv0rCEAAwCgYIKoEcz1UBg3UwgYwxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjELMAkGA1UEBwwCY3MxDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTEQMA4GA1UEAwwHUk9PVCBDQTAeFw0yNDA5MTAxNjAwMDBaFw00NDA5MTAxNjAwMDBaMIGMMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFaHVuYW4xCzAJBgNVBAcMAmNzMQ0wCwYDVQQJDARsdWd1MR8wHQYJKoZIhvcNAQkBFhBjcnlwdG9fbHRAcXEuY29tMQ8wDQYDVQQKDAZxaW1pbmcxDTALBgNVBAsMBG1pbWExEDAOBgNVBAMMB1JPT1QgQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQVwDIJ06OJA01aJYSPHjl1Lj9ed8wvfbZNSpm8AKoYl5rHr5bdi+ZXpiKtkJT6Z7c+ifAGojkNdkp4exGuON07o0IwQDAdBgNVHQ4EFgQUMqOkLWjNMgp6zVxjz7RiS32jm4wwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAcYwCgYIKoEcz1UBg3UDSAAwRQIhAOWmHXxt/Vg4ozuKSbYUUQmbcYvBq6w34c2fJQbbztjGAiAKZlc4RnxRER+uZW62gA2lKpEZeSXmb/8F1JX46GVSyg==";
    public static final String subCACert = "MIICajCCAhGgAwIBAgIIGXLSv1UCEAAwCgYIKoEcz1UBg3UwgYUxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjELMAkGA1UEBwwCY3MxDTALBgNVBAkMBGx1Z3UxGDAWBgkqhkiG9w0BCQEWCUtFWUBRUUNPTTEPMA0GA1UECgwGcWltaW5nMQ0wCwYDVQQLDARtaW1hMRAwDgYDVQQDDAdST09UIENBMB4XDTI0MDkxMDE2MDAwMFoXDTQ0MDkxMDE2MDAwMFowgYsxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjELMAkGA1UEBwwCY3MxDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTEPMA0GA1UEAwwGU1VCIENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEfag3tCvxek4enwUWvtW/c5jpiY3WFHxRkb4fmJyVKBh7Nne5PO/hoexhRvHl9D3slOSuqBj5UGHbJ5KtsSy8CaNjMGEwHQYDVR0OBBYEFF1dip7OMDvnTWAHuMMJKqvGnu2dMB8GA1UdIwQYMBaAFDKjpC1ozTIKes1cY8+0Ykt9o5uMMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgHGMAoGCCqBHM9VAYN1A0cAMEQCIGBs4ifZKUjo23jDv0Qa+rvICAlvGBvgTqJUbP6xyiIYAiApbB4N4yXvJ2QY1Ewxfy1Lyb37R9DU+2gSW7c2NLoebw==";
    public PublicKey issuerPublicKey;
    public PrivateKey issuerPrivateKey;
    public PublicKey rootPublicKey;
    public PrivateKey rootPrivateKey;

    public SM2X509CertMaker() {
        try {
            rootPublicKey = BCECUtil.convertX509ToECPublicKey(HexUtil.decodeHex(rootPub));
            rootPrivateKey = BCECUtil.convertPKCS8ToECPrivateKey(HexUtil.decodeHex(rootPri));

            issuerPublicKey = BCECUtil.convertX509ToECPublicKey(HexUtil.decodeHex(issuerPublicKeyBase64));
            issuerPrivateKey = BCECUtil.convertPKCS8ToECPrivateKey(HexUtil.decodeHex(issuerPrivateKeyBase64));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * T10：覆盖默认内置 issuer 公私钥（用于自建 CA 签发）。
     * 返回 this 以支持链式调用。
     */
    public SM2X509CertMaker withIssuerKeys(PublicKey issuerPub, PrivateKey issuerPriv) {
        this.issuerPublicKey = issuerPub;
        this.issuerPrivateKey = issuerPriv;
        return this;
    }

    public X509Certificate makeRootCACert(CertCreateDTO dto) {
        // 根证书使用同一个DN
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        PublicKey rootPub = new SM2PublicKey(rootPublicKey.getAlgorithm(), (BCECPublicKey) rootPublicKey);
        Date notBefore = DateUtil.beginOfDay(DateUtil.date());
        Date notAfter = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
        try {
            byte[] rootCSR = CommonUtil.createCSR(subjectDN, rootPub, rootPrivateKey, SIGN_ALGO_SM3WITHSM2).getEncoded();
            KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyCertSign | KeyUsage.cRLSign);
            X509Certificate rootCACert = makeCACertificate(CertLevel.RootCA, null, rootCSR, usage, null, subjectDN, subjectDN, notBefore,
                    notAfter, rootPublicKey, rootPrivateKey);
            boolean flag = SM2X509CertMaker.isTruested(Base64.encode(rootCACert.getEncoded()),
                    Base64.encode(rootCACert.getEncoded()));
            if (!flag) {
                //     ResultAssert.throwFail(GenerateCertApiCode.GENERATE_USER_CERT_VERIFY_FAILED);
                throw new RuntimeException("证书验证不通过");
            }
            return rootCACert;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public X509Certificate makeSubCACert(CertCreateDTO dto, X500Name issueDN) {
        // 根证书使用同一个DN
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        // KeyPair userKeyPair = SM2X509CertMaker.softSm2KeyPair();
        PublicKey rootPub = new SM2PublicKey(issuerPublicKey.getAlgorithm(), (BCECPublicKey) issuerPublicKey);
        System.out.println("caPub=" + HexUtil.encodeHexStr(issuerPublicKey.getEncoded()));
        System.out.println("caPri=" + HexUtil.encodeHexStr(issuerPrivateKey.getEncoded()));

        Date notBefore = DateUtil.beginOfDay(DateUtil.date());
        Date notAfter = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
        try {
            byte[] rootCSR = CommonUtil.createCSR(subjectDN, rootPub, issuerPrivateKey, SIGN_ALGO_SM3WITHSM2).getEncoded();
            KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyCertSign | KeyUsage.cRLSign);
            X509Certificate subCACert = makeCACertificate(CertLevel.SubCA, null, rootCSR, usage, null, subjectDN, issueDN, notBefore,
                    notAfter, rootPublicKey, rootPrivateKey);
            boolean flag = SM2X509CertMaker.isTruested(Base64.encode(subCACert.getEncoded()), rootCACert);
            if (!flag) {
                throw new RuntimeException("证书验证不通过");
            }
            return subCACert;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public X509CertificateHolder makeUserCertHolder(KeyPair userKeyPair, CertCreateDTO dto, CertDescInfo descInfo) {
        X500Name issuerDN = SM2X509CertMaker.buildSubjectDN(descInfo);
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        SM2PublicKey userPub = new SM2PublicKey(userKeyPair.getPublic().getAlgorithm(), (BCECPublicKey) userKeyPair.getPublic());
        try {
            Date notBefore = DateUtil.beginOfDay(DateUtil.date());
            Date notAfter = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
            byte[] userCSR = CommonUtil.createCSR(subjectDN, userPub, userKeyPair.getPrivate(), SIGN_ALGO_SM3WITHSM2).getEncoded();
            // T02: 用户可覆盖；未指定时保留 SM2 旧默认（数字签名/密钥协商/数据加密/密钥加密）
            KeyUsage defaultUsage = new KeyUsage(
                    KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment);
            KeyPurposeId[] defaultEku = new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
            KeyUsage usage = CertExtensionResolver.resolveKeyUsage(dto.getKeyUsages(), defaultUsage);
            KeyPurposeId[] eku = CertExtensionResolver.resolveExtendedKeyUsages(dto.getExtendedKeyUsages(), defaultEku);
            List<GeneralName> sans = CertExtensionResolver.resolveSubjectAltNames(dto.getSubjectAltNames());
            BasicConstraints bc = CertExtensionResolver.resolveBasicConstraints(
                    dto.getBasicConstraintsCA(), null, true);
            return makeUserCertificateHolder(CertLevel.EndEntity, null, userCSR, usage, eku,
                    sans, bc, issuerDN, notBefore, notAfter);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public X509CertificateHolder makeUserCertHolder(byte[] userCSR, CertDescInfo descInfo) {
        // CSR-only path（无 dto）：保留旧默认行为
        return makeUserCertHolder(userCSR, descInfo, null);
    }

    /**
     * CSR 路径并允许通过 {@link CertCreateDTO} 覆盖扩展项（T02）。dto 为 null → 走旧默认。
     */
    public X509CertificateHolder makeUserCertHolder(byte[] userCSR, CertDescInfo descInfo, CertCreateDTO dto) {
        X500Name issuerDN = SM2X509CertMaker.buildSubjectDN(descInfo);
        try {
            Date notBefore = DateUtil.beginOfDay(DateUtil.date());
            Date notAfter = DateUtil.offsetMonth(notBefore, 5);
            KeyUsage defaultUsage = new KeyUsage(
                    KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment);
            KeyPurposeId[] defaultEku = new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
            KeyUsage usage = dto == null ? defaultUsage
                    : CertExtensionResolver.resolveKeyUsage(dto.getKeyUsages(), defaultUsage);
            KeyPurposeId[] eku = dto == null ? defaultEku
                    : CertExtensionResolver.resolveExtendedKeyUsages(dto.getExtendedKeyUsages(), defaultEku);
            List<GeneralName> sans = dto == null ? new LinkedList<>()
                    : CertExtensionResolver.resolveSubjectAltNames(dto.getSubjectAltNames());
            BasicConstraints bc = CertExtensionResolver.resolveBasicConstraints(
                    dto == null ? null : dto.getBasicConstraintsCA(), null, true);
            return makeUserCertificateHolder(CertLevel.EndEntity, null, userCSR, usage, eku,
                    sans, bc, issuerDN, notBefore, notAfter);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * @param keyUsage 证书用途
     * @param csr      CSR
     * @return
     * @throws Exception
     */
    private X509Certificate makeCACertificate(CertLevel certLevel, Integer pathLenConstrain, byte[] csr, KeyUsage keyUsage,
            KeyPurposeId[] extendedKeyUsages, X500Name subjectDN, X500Name issuerDN, Date notBefore, Date notAfter, PublicKey issPub,
            PrivateKey issPriv) throws Exception {
        if (certLevel == CertLevel.EndEntity) {
            if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
                throw new IllegalArgumentException("keyusage keyCertSign is not allowed in EndEntity Certificate");
            }
        }

        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub = request.getSubjectPublicKeyInfo();

        String commonName = null;

        List<GeneralName> subjectAltNames = new LinkedList<>();

        boolean selfSignedEECert = false;
        switch (certLevel) {
            case RootCA:
                if (issuerDN.equals(subjectDN)) {
                    subjectDN = issuerDN;
                } else {
                    throw new IllegalArgumentException("subject != issuer for certLevel " + CertLevel.RootCA);
                }
                break;
            case SubCA:
                if (issuerDN.equals(subjectDN)) {
                    throw new IllegalArgumentException("subject MUST not equals issuer for certLevel " + certLevel);
                }
                break;
            default:
                if (issuerDN.equals(subjectDN)) {
                    selfSignedEECert = true;
                    subjectDN = issuerDN;
                }
        }
        BigInteger serialNumber = BigInteger.valueOf(snowflake.nextId());
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN, subPub);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPub));
        if (certLevel != CertLevel.RootCA && !selfSignedEECert) {
            v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
        }

        BasicConstraints basicConstraints;
        if (certLevel == CertLevel.EndEntity) {
            basicConstraints = new BasicConstraints(false);
        } else {
            basicConstraints = pathLenConstrain == null ? new BasicConstraints(true) : new BasicConstraints(pathLenConstrain.intValue());
        }
        v3CertGen.addExtension(Extension.basicConstraints, true, basicConstraints);

        v3CertGen.addExtension(Extension.keyUsage, true, keyUsage);

        if (extendedKeyUsages != null) {
            ExtendedKeyUsage xku = new ExtendedKeyUsage(extendedKeyUsages);
            v3CertGen.addExtension(Extension.extendedKeyUsage, false, xku);

            boolean forSSLServer = false;
            for (KeyPurposeId purposeId : extendedKeyUsages) {
                if (KeyPurposeId.id_kp_serverAuth.equals(purposeId)) {
                    forSSLServer = true;
                    break;
                }
            }

            if (forSSLServer) {
                if (commonName == null) {
                    throw new IllegalArgumentException("commonName must not be null");
                }
                GeneralName name = new GeneralName(GeneralName.dNSName, new DERIA5String(commonName, true));
                subjectAltNames.add(name);
            }
        }

        if (!subjectAltNames.isEmpty()) {
            v3CertGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }
        X509CertificateHolder v3CertHolder = toSoftSignCertHolder(v3CertGen, issPub, issPriv);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                v3CertHolder);
        cert.verify(issPub);

        return cert;
    }


    /**
     * @param keyUsage 证书用途
     * @param csr      CSR
     * @return
     * @throws Exception
     */
    private X509CertificateHolder makeUserCertificateHolder(CertLevel certLevel, Integer pathLenConstrain, byte[] csr, KeyUsage keyUsage,
            KeyPurposeId[] extendedKeyUsages, List<GeneralName> customSans, BasicConstraints bcOverride,
            X500Name issuerDN, Date notBefore, Date notAfter) throws Exception {
        if (certLevel == CertLevel.EndEntity) {
            if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
                throw new IllegalArgumentException("keyusage keyCertSign is not allowed in EndEntity Certificate");
            }
        }

        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub = request.getSubjectPublicKeyInfo();

        X500Name subject = request.getSubject();

        List<GeneralName> subjectAltNames = new LinkedList<>();
        if (customSans != null && !customSans.isEmpty()) {
            subjectAltNames.addAll(customSans);
        }

        boolean selfSignedEECert = false;
        switch (certLevel) {
            case RootCA:
                if (issuerDN.equals(subject)) {
                    subject = issuerDN;
                } else {
                    throw new IllegalArgumentException("subject != issuer for certLevel " + CertLevel.RootCA);
                }
                break;
            case SubCA:
                if (issuerDN.equals(subject)) {
                    throw new IllegalArgumentException("subject MUST not equals issuer for certLevel " + certLevel);
                }
                break;
            default:
                if (issuerDN.equals(subject)) {
                    selfSignedEECert = true;
                    subject = issuerDN;
                }
        }

        BigInteger serialNumber = BigInteger.valueOf(snowflake.nextId());
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subject, subPub);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (certLevel != CertLevel.RootCA && !selfSignedEECert) {
            v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issuerPublicKey.getEncoded())));
        }
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPub));


        AccessDescription[] accessDescriptions = new AccessDescription[]{new AccessDescription(AccessDescription.id_ad_caIssuers,
                new GeneralName(6, "https://www.venus.com/")), new AccessDescription(AccessDescription.id_ad_ocsp,
                new GeneralName(6, "http://www.venus.com/ocsp"))};
        v3CertGen.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions));


        BasicConstraints basicConstraints;
        if (bcOverride != null) {
            basicConstraints = bcOverride;
        } else if (certLevel == CertLevel.EndEntity) {
            basicConstraints = new BasicConstraints(false);
        } else {
            basicConstraints = pathLenConstrain == null ? new BasicConstraints(true) : new BasicConstraints(pathLenConstrain.intValue());
        }
        v3CertGen.addExtension(Extension.basicConstraints, false, basicConstraints);

        v3CertGen.addExtension(Extension.keyUsage, true, keyUsage);

        if (extendedKeyUsages != null) {
            ExtendedKeyUsage xku = new ExtendedKeyUsage(extendedKeyUsages);
            v3CertGen.addExtension(Extension.extendedKeyUsage, false, xku);

            boolean forSSLServer = false;
            for (KeyPurposeId purposeId : extendedKeyUsages) {
                if (KeyPurposeId.id_kp_serverAuth.equals(purposeId)) {
                    forSSLServer = true;
                    break;
                }
            }
        }
        if (!subjectAltNames.isEmpty()) {
            v3CertGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }
        return toSoftSignCertHolder(v3CertGen, issuerPublicKey, issuerPrivateKey);
    }

    public static X500Name buildSubjectDN(CertCreateDTO dto) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, dto.getDn_c().toUpperCase());
        if (StringUtils.isNotBlank(dto.getDn_st())) {
            builder.addRDN(BCStyle.ST, dto.getDn_st());
        }
        if (StringUtils.isNotBlank(dto.getDn_l())) {
            builder.addRDN(BCStyle.L, dto.getDn_l());
        }
        if (StringUtils.isNotBlank(dto.getDn_street())) {
            builder.addRDN(BCStyle.STREET, dto.getDn_street());
        }
        if (StringUtils.isNotBlank(dto.getDn_email())) {
            builder.addRDN(BCStyle.E, dto.getDn_email());
        }
        builder.addRDN(BCStyle.O, dto.getDn_o());
        builder.addRDN(BCStyle.OU, dto.getDn_ou());
        builder.addRDN(BCStyle.CN, dto.getDn_cn());

        return builder.build();
    }

    public static X500Name buildSubjectDN(CertDescInfo descInfo) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, descInfo.getCountry().toUpperCase());
        if (StringUtils.isNotBlank(descInfo.getProvince())) {
            builder.addRDN(BCStyle.ST, descInfo.getProvince());
        }
        if (StringUtils.isNotBlank(descInfo.getCity())) {
            builder.addRDN(BCStyle.L, descInfo.getCity());
        }
        if (StringUtils.isNotBlank(descInfo.getStreet())) {
            builder.addRDN(BCStyle.STREET, descInfo.getStreet());
        }
        if (StringUtils.isNotBlank(descInfo.getEmail())) {
            builder.addRDN(BCStyle.E, descInfo.getEmail());
        }
        builder.addRDN(BCStyle.O, descInfo.getOrganization());
        builder.addRDN(BCStyle.OU, descInfo.getOrganizationUnit());
        builder.addRDN(BCStyle.CN, descInfo.getUniversalName());
        return builder.build();
    }

    public static KeyPair softSm2KeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", bcProvider);
            keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("sm2p256v1"));
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private X509CertificateHolder toSoftSignCertHolder(X509v3CertificateBuilder builder, PublicKey issPub,
            PrivateKey issPriv) throws OperatorCreationException {
        if (issPub.getAlgorithm().equals("EC")) {
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGN_ALGO_SM3WITHSM2);
            contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ContentSigner contentSigner = contentSignerBuilder.build(issPriv);
            return builder.build(contentSigner);
        }
        throw new OperatorCreationException("Unsupported PublicKey Algorithm:" + issPub.getAlgorithm());
    }


    public static boolean isTruested(String cert, String rootCert) {
        cert = buildCert(cert);
        rootCert = buildCert(rootCert);

        X509Certificate[] certificates;
        try {
            certificates = readPemCertChain(cert);
        } catch (Exception var9) {
            log.error("读取证书失败", var9);
            throw new RuntimeException(var9);
        }

        ArrayList rootCerts = new ArrayList();

        try {
            X509Certificate[] certs = readPemCertChain(rootCert);
            X509Certificate[] var5 = certs;
            int var6 = certs.length;

            for (int var7 = 0; var7 < var6; ++var7) {
                X509Certificate c = var5[var7];
                rootCerts.add(c);
            }
        } catch (Exception var10) {
            log.error("读取根证书失败", var10);
            throw new RuntimeException(var10);
        }

        return verifyCertChain(certificates, (X509Certificate[]) rootCerts.toArray(new X509Certificate[rootCerts.size()]));
    }

    public static String buildCert(String cert) {
        if (cert != null && !cert.startsWith("-----BEGIN CERTIFICATE-----\n")) {
            cert = "-----BEGIN CERTIFICATE-----\n" + cert;
        }

        if (cert != null && !cert.endsWith("\n-----END CERTIFICATE-----")) {
            cert = cert + "\n-----END CERTIFICATE-----";
        }

        return cert;
    }

    public static boolean verifyCert(X509Certificate cert, X509Certificate[] rootCerts) {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException var8) {
            log.error("证书已经过期", var8);
            return false;
        } catch (CertificateNotYetValidException var9) {
            log.error("证书未激活", var9);
            return false;
        }

        Map<Principal, X509Certificate> subjectMap = new HashMap();
        X509Certificate[] var3 = rootCerts;
        int var4 = rootCerts.length;

        for (int var5 = 0; var5 < var4; ++var5) {
            X509Certificate root = var3[var5];
            subjectMap.put(root.getSubjectDN(), root);
        }

        Principal issuerDN = cert.getIssuerDN();
        X509Certificate issuer = (X509Certificate) subjectMap.get(issuerDN);
        if (issuer == null) {
            log.error("证书链验证失败");
            return false;
        } else {
            try {
                PublicKey publicKey = issuer.getPublicKey();
                verifySignature(publicKey, cert);
                return true;
            } catch (Exception var7) {
                log.error("证书链验证失败", var7);
                return false;
            }
        }
    }

    public static String getRootCertSN(String rootCertContent) {
        String rootCertSN = null;

        try {
            X509Certificate[] x509Certificates = readPemCertChain(rootCertContent);
            MessageDigest md = MessageDigest.getInstance("MD5");
            X509Certificate[] var4 = x509Certificates;
            int var5 = x509Certificates.length;

            for (int var6 = 0; var6 < var5; ++var6) {
                X509Certificate c = var4[var6];
                if (c.getSigAlgOID().startsWith("1.2.840.113549.1.1")) {
                    md.update((c.getIssuerX500Principal().getName() + c.getSerialNumber()).getBytes(StandardCharsets.UTF_8));
                    String certSN = (new BigInteger(1, md.digest())).toString(16);
                    certSN = fillMD5(certSN);
                    if (org.springframework.util.StringUtils.isEmpty(rootCertSN)) {
                        rootCertSN = certSN;
                    } else {
                        rootCertSN = rootCertSN + "_" + certSN;
                    }
                }
            }
        } catch (Exception var9) {
        }

        return rootCertSN;
    }

    public static String getCertSN(X509Certificate x509Certificate) throws NoSuchAlgorithmException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update((x509Certificate.getIssuerX500Principal().getName() + x509Certificate.getSerialNumber()).getBytes(
                    StandardCharsets.UTF_8));
            String certSN = (new BigInteger(1, md.digest())).toString(16);
            certSN = fillMD5(certSN);
            return certSN;
        } catch (NoSuchAlgorithmException var3) {
            throw new NoSuchAlgorithmException(var3);
        }
    }

    public static X509Certificate[] readPemCertChain(String cert) throws CertificateException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8));
        CertificateFactory factory = CertificateFactory.getInstance("X.509", bcProvider);
        Collection<? extends Certificate> certificates = factory.generateCertificates(inputStream);
        return (X509Certificate[]) certificates.toArray(new X509Certificate[certificates.size()]);
    }

    private static String fillMD5(String md5) {
        return md5.length() == 32 ? md5 : fillMD5("0" + md5);
    }

    private static boolean verifyCertChain(X509Certificate[] certs, X509Certificate[] rootCerts) {
        boolean sorted = sortByDn(certs);
        if (!sorted) {
            log.error("证书链验证失败：不是完整的证书链");
            return false;
        } else {
            X509Certificate prev = certs[0];
            boolean firstOK = verifyCert(prev, rootCerts);
            if (firstOK && certs.length != 1) {
                for (int i = 1; i < certs.length; ++i) {
                    try {
                        X509Certificate cert = certs[i];

                        try {
                            cert.checkValidity();
                        } catch (CertificateExpiredException var8) {
                            log.error("证书已经过期", var8);
                            return false;
                        } catch (CertificateNotYetValidException var9) {
                            log.error("证书未激活", var9);
                            return false;
                        }

                        verifySignature(prev.getPublicKey(), cert);
                        prev = cert;
                    } catch (Exception var10) {
                        log.error("证书链验证失败", var10);
                        return false;
                    }
                }

                return true;
            } else {
                return firstOK;
            }
        }
    }

    private static boolean sortByDn(X509Certificate[] certs) {
        Map<Principal, X509Certificate> subjectMap = new HashMap();
        Map<Principal, X509Certificate> issuerMap = new HashMap();
        boolean hasSelfSignedCert = false;
        X509Certificate[] var4 = certs;
        int var5 = certs.length;

        int i;
        for (i = 0; i < var5; ++i) {
            X509Certificate cert = var4[i];
            if (isSelfSigned(cert)) {
                if (hasSelfSignedCert) {
                    return false;
                }

                hasSelfSignedCert = true;
            }

            Principal subjectDN = cert.getSubjectDN();
            Principal issuerDN = cert.getIssuerDN();
            subjectMap.put(subjectDN, cert);
            issuerMap.put(issuerDN, cert);
        }

        List<X509Certificate> certChain = new ArrayList();
        X509Certificate current = certs[0];
        addressingUp(subjectMap, certChain, current);
        addressingDown(issuerMap, certChain, current);
        if (certs.length != certChain.size()) {
            return false;
        } else {
            for (i = 0; i < certChain.size(); ++i) {
                certs[i] = (X509Certificate) certChain.get(i);
            }

            return true;
        }
    }

    private static void verifySignature(PublicKey publicKey,
            X509Certificate cert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        cert.verify(publicKey, bcProvider.getName());
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }

    private static void addressingUp(Map<Principal, X509Certificate> subjectMap, List<X509Certificate> certChain, X509Certificate current) {
        certChain.add(0, current);
        if (!isSelfSigned(current)) {
            Principal issuerDN = current.getIssuerDN();
            X509Certificate issuer = (X509Certificate) subjectMap.get(issuerDN);
            if (issuer != null) {
                addressingUp(subjectMap, certChain, issuer);
            }
        }
    }

    private static void addressingDown(Map<Principal, X509Certificate> issuerMap, List<X509Certificate> certChain,
            X509Certificate current) {
        Principal subjectDN = current.getSubjectDN();
        X509Certificate subject = (X509Certificate) issuerMap.get(subjectDN);
        if (subject != null) {
            if (!isSelfSigned(subject)) {
                certChain.add(subject);
                addressingDown(issuerMap, certChain, subject);
            }
        }
    }

    // 生成P7B文件的byte[]
    public static byte[] generateP7B(List<X509Certificate> certificates) throws CertificateEncodingException, CMSException, IOException {
        // 创建 CMSSignedDataGenerator 来生成 P7B 数据
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        // 使用证书链构建 CertStore
        JcaCertStore certStore = new JcaCertStore(certificates);
        generator.addCertificates(certStore);
        // 生成空的 CMSSignedData (不包含签名的数据，只包含证书链)
        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(new byte[0]);
        CMSSignedData signedData = generator.generate(cmsData, false); // 不需要签名，只打包证书链

        // 返回生成的 P7B 数据 (编码为 DER 格式)
        return signedData.getEncoded();
    }

    public static byte[] toPEMFormat(Key key, String type) throws IOException {
        return toPEMFormat(key.getEncoded(), type);
    }

    public static byte[] toPEMFormat(byte[] key, String type) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(byteArrayOutputStream))) {
            pemWriter.writeObject(new PemObject(type, key));
            pemWriter.flush();
        }
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] toKeyPem(PrivateKey key) {
        if (!(key instanceof PrivateKeyInfo)) {
            throw new IllegalArgumentException("toKeyPem parse error.");
        }
        try {
            return toPEMFormat(key, "PRIVATE KEY INFO");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new IllegalArgumentException("toKeyPem parse error.");
        }
    }

    public static byte[] toPriPem(PrivateKey key) {
        if (!(key instanceof PrivateKeyInfo)) {
            throw new BusinessException("toPriPem parse error.");
        }
        return toPriPem((PrivateKeyInfo) key);
    }
    public static byte[] toPriPem(PrivateKeyInfo keyInfo) {
        try {
            return combineBytes(
                    toPEMFormat(keyInfo.getPrivateKeyAlgorithm().getParameters().toASN1Primitive().getEncoded(), "EC PARAMETERS"),
                    toPEMFormat(keyInfo.getPrivateKey().getOctets(), "EC PRIVATE KEY"));
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new IllegalArgumentException("toPriPem parse error.");
        }
    }

    /**
           * 合并两个字节数组。
           *
           * @param first  第一个字节数组（可为 null）
           * @param second 第二个字节数组（可为 null）
           * @return 合并后的新数组；若两个参数均为 null，则返回空数组
           */
     public static byte[] combineBytes(byte[] first, byte[] second) {
         if (first == null && second == null) {
             return new byte[0];
         }
         if (first == null) {
             return second.clone();
         }
         if (second == null) {
             return first.clone();
         }
         byte[] result = new byte[first.length + second.length];
         System.arraycopy(first, 0, result, 0, first.length);
         System.arraycopy(second, 0, result, first.length, second.length);
         return result;
     }

    // 将公钥转换为 ASN.1 格式的 byte[]
    public static byte[] convertSubjectPublicKeyInfo(PublicKey publicKey) throws Exception {
        AsymmetricKeyParameter publicKeyParam = null;
        if (publicKey instanceof DSAPublicKey) {
            publicKeyParam = DSAUtil.generatePublicKeyParameter(publicKey);
        } else if (publicKey instanceof BCECPublicKey) {
            publicKeyParam = ECUtil.generatePublicKeyParameter(publicKey); // SM2 使用 ECUtil
        } else if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            publicKeyParam = new RSAKeyParameters(false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
        } else {
            throw new IllegalArgumentException("unsupported Algorithm.");
        }
        // 使用 SubjectPublicKeyInfoFactory 将其转换为 ASN.1 格式
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParam);
        return publicKeyInfo.getEncoded(); // 获取 ASN.1 编码的 byte[]
    }

    // 将私钥转换为 ASN.1 格式的 byte[]
    public static byte[] convertPrivateKeyInfoBytes(PrivateKey privateKey) throws Exception {
        return convertPrivateKeyInfo(privateKey).getEncoded(); // 获取 ASN.1 编码的 byte[]
    }
    public static PrivateKeyInfo convertPrivateKeyInfo(PrivateKey privateKey) throws Exception {
        AsymmetricKeyParameter privateKeyParam;
        if (privateKey instanceof DSAPrivateKey) {
            privateKeyParam = DSAUtil.generatePrivateKeyParameter(privateKey);
        } else if (privateKey instanceof BCECPrivateKey) {
            privateKeyParam = ECUtil.generatePrivateKeyParameter(privateKey); // SM2 使用 ECUtil
        } else if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
            privateKeyParam = new RSAPrivateCrtKeyParameters(key.getModulus(), key.getPublicExponent(), key.getPrivateExponent(),
                    key.getPrimeP(), key.getPrimeQ(), key.getPrimeExponentP(), key.getPrimeExponentQ(), key.getCrtCoefficient());
        } else {
            throw new IllegalArgumentException("unsupported Algorithm.");
        }
        // 使用 PrivateKeyInfoFactory 将其转换为 ASN.1 格式
        return PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParam);
    }
    /**
     * 将加密私钥用接收方签名证书的 SM2 公钥封装为 PKCS#7 数字信封 (CMS EnvelopedData)。
     * <p>
     * 信封结构：CMSEnvelopedData
     *   └─ RecipientInfo: KeyTransRecipientInfo（SM2 加密 + OID 1.2.840.10045.2.1）
     *   └─ EncryptedContentInfo: SM4-CBC 加密的私钥 PKCS#8 字节
     * <p>
     * 接收方解密步骤：
     *   1. 用签名私钥（ECPrivateKey）解密 RecipientInfo 中的对称密钥（SM4 Key）
     *   2. 用 SM4 Key 解密 EncryptedContentInfo，还原 PKCS#8 字节
     *   3. 解析 PKCS#8 得到加密私钥
     *
     * @param privateKeyPkcs8Bytes 待保护的加密私钥（PKCS#8 DER 编码）
     * @param recipientCert        接收方签名证书（其公钥用于加密对称密钥）
     * @return CMS EnvelopedData DER 字节
     */
    public static byte[] wrapPrivateKeyAsEnvelope(byte[] privateKeyPkcs8Bytes, X509Certificate recipientCert) throws Exception {
        // 1. 生成随机 SM4 对称密钥（128 bit）
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.init(128, new SecureRandom());
        SecretKey sm4Key = keyGen.generateKey();

        // 2. 用接收方签名证书的 SM2 公钥加密 SM4 密钥
        Cipher sm2Cipher = Cipher.getInstance("SM2", BouncyCastleProvider.PROVIDER_NAME);
        sm2Cipher.init(Cipher.ENCRYPT_MODE, recipientCert.getPublicKey(), new SecureRandom());
        byte[] encryptedSm4Key = sm2Cipher.doFinal(sm4Key.getEncoded());

        // 3. 构造 KeyTransRecipientInfo：持有加密后的 SM4 密钥
        //    issuerAndSerialNumber 用于标识接收方证书
        org.bouncycastle.asn1.x509.Certificate bcCert =
                org.bouncycastle.asn1.x509.Certificate.getInstance(recipientCert.getEncoded());
        org.bouncycastle.asn1.cms.IssuerAndSerialNumber issuerAndSerial =
                new org.bouncycastle.asn1.cms.IssuerAndSerialNumber(
                        bcCert.getIssuer(), bcCert.getSerialNumber().getValue());
        // SM2 加密算法 OID
        ASN1ObjectIdentifier sm2OID = new ASN1ObjectIdentifier("1.2.156.10197.1.301");
        org.bouncycastle.asn1.cms.KeyTransRecipientInfo recipientInfo =
                new org.bouncycastle.asn1.cms.KeyTransRecipientInfo(
                        new org.bouncycastle.asn1.cms.RecipientIdentifier(issuerAndSerial),
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(sm2OID),
                        new DEROctetString(encryptedSm4Key));

        // 4. 用 SM4-CBC 加密私钥原文
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher sm4Cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
        sm4Cipher.init(Cipher.ENCRYPT_MODE, sm4Key,
                new javax.crypto.spec.IvParameterSpec(iv));
        byte[] encryptedContent = sm4Cipher.doFinal(privateKeyPkcs8Bytes);

        // 5. 构造 EncryptedContentInfo
        ASN1ObjectIdentifier sm4CbcOID = new ASN1ObjectIdentifier("1.2.156.10197.1.104.2");
        // SM4-CBC AlgorithmIdentifier 含 IV 参数
        org.bouncycastle.asn1.x509.AlgorithmIdentifier sm4AlgId =
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        sm4CbcOID, new DEROctetString(iv));
        org.bouncycastle.asn1.cms.EncryptedContentInfo encContentInfo =
                new org.bouncycastle.asn1.cms.EncryptedContentInfo(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.data,
                        sm4AlgId,
                        new DEROctetString(encryptedContent));

        // 6. 组装 EnvelopedData
        ASN1EncodableVector recipientInfoVec = new ASN1EncodableVector();
        recipientInfoVec.add(new org.bouncycastle.asn1.cms.RecipientInfo(
                new org.bouncycastle.asn1.cms.KeyTransRecipientInfo(
                        new org.bouncycastle.asn1.cms.RecipientIdentifier(issuerAndSerial),
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(sm2OID),
                        new DEROctetString(encryptedSm4Key))));
        org.bouncycastle.asn1.cms.EnvelopedData envelopedData =
                new org.bouncycastle.asn1.cms.EnvelopedData(
                        null,
                        new DERSet(recipientInfoVec),
                        encContentInfo,
                        (org.bouncycastle.asn1.cms.Attributes) null);

        // 7. 包装为 ContentInfo 并 DER 编码输出
        org.bouncycastle.asn1.cms.ContentInfo contentInfo =
                new org.bouncycastle.asn1.cms.ContentInfo(
                        org.bouncycastle.asn1.cms.CMSObjectIdentifiers.envelopedData,
                        envelopedData);
        return contentInfo.getEncoded(ASN1Encoding.DER);
    }

    }
