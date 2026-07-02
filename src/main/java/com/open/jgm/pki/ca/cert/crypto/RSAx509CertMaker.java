/*
 * Copyright 2026 open-gm-jca contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.open.jgm.pki.ca.cert.crypto;

import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.util.CertExtensionResolver;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.HexUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * RSA X.509 证书签发工具类（单证书，SHA256withRSA，RSA-2048）。
 * <p>
 * 根CA密钥对硬编码（由 main() 离线生成），子CA密钥对在类加载时动态生成并签发，
 * CA证书字符串（rootCACert / subCACert）在静态初始化块中生成后存入公共静态字段，
 * 供 RsaCertController 静态块直接引用。
 */
@Slf4j
public class RSAx509CertMaker {

    // ----------------------------------------------------------------
    // 枚举 & 常量
    // ----------------------------------------------------------------
    private enum CertLevel { RootCA, SubCA, EndEntity }

    private static final SecureRandom SERIAL_RANDOM = new SecureRandom();
    static final BouncyCastleProvider BC = new BouncyCastleProvider();

    public static final String SIGN_ALGO = "SHA256withRSA";
    public static final String PASSWORD  = "";

    // ----------------------------------------------------------------
    // 硬编码根CA密钥对（X509/PKCS8 DER hex，离线生成后固定）
    // ----------------------------------------------------------------
    static final String ROOT_PUB_HEX =
            "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
            + "00adc67d91ca68f853375b45731270e4f2492637c8cbf446f0f64a4b88698e"
            + "4db1c9cc651a7beca51c6039c4e7842811fb49ed8477b42f24f52f5ecfb8f2"
            + "b2c18736c56dea60dfb8c9c3bab242b9a71f03860a2fe9d44f5dc84d7e497f"
            + "9413e58f911c791e0e540a80cc5b893b5f49594ba92e7f070b7269b51caccd"
            + "4f295290392f4d501520bc462adb6bf3663fb0034d42b17177e747ad13fd6a"
            + "ff3801544e101c49549d77ab0063912f2b062b8d209598810220a38c7208aa"
            + "de3fdcfe926eca3609425b6313abeb4421d4119acbd182113266c445cedcdd"
            + "c8d3a62a2e4a26eac60ffc790908c9a2d6cc8d6a976890891ed3a4ad73fb39"
            + "ddca5f211b1ff787af0203010001";

    static final String ROOT_PRI_HEX =
            "308204be020100300d06092a864886f70d0101010500048204a8308204a40201"
            + "000282010100adc67d91ca68f853375b45731270e4f2492637c8cbf446f0f6"
            + "4a4b88698e4db1c9cc651a7beca51c6039c4e7842811fb49ed8477b42f24f5"
            + "2f5ecfb8f2b2c18736c56dea60dfb8c9c3bab242b9a71f03860a2fe9d44f5d"
            + "c84d7e497f9413e58f911c791e0e540a80cc5b893b5f49594ba92e7f070b72"
            + "69b51caccd4f295290392f4d501520bc462adb6bf3663fb0034d42b17177e7"
            + "47ad13fd6aff3801544e101c49549d77ab0063912f2b062b8d209598810220"
            + "a38c7208aade3fdcfe926eca3609425b6313abeb4421d4119acbd182113266"
            + "c445cedcddc8d3a62a2e4a26eac60ffc790908c9a2d6cc8d6a976890891ed"
            + "3a4ad73fb39ddca5f211b1ff787af0203010001028201000f79d06005fb303"
            + "655053b5ba2a64c35699f4e33833a6780f92627b0e7d9a500b2dc919a78b3d"
            + "c0679695ba854a42ee9c6ad30f16a2a12ac054277d45c44e028570fe11890f"
            + "50ba3685b7d99a4a806028dd2e56e791a725b2ecf92e31a40655ed2490b5e4"
            + "a5f60aa14c9082131fcb9c79bb308dc0b406eba92e9aec520847a547fa64c1"
            + "ae270716b3bb5c8aff2464e0be82de9da03087fde49f8fc5c2c7af04bf0003"
            + "53b791fa62255791a088823eaf0c99899b603b52f5da12034e5341db553177"
            + "0a6b81a1ef9341484faa83247c595b484b0b984d7e4ab644217faf036740a4"
            + "4e7b3eb15185fe2da9e04a858114b5e3fbbc8870e8117ee8f09a221bf18f13"
            + "102818100e9bad0b63731bf3d0c93fca89945776e136db99555da3d39f4e9e"
            + "3c126a9299be66256eed75301f6d9033e43b69f61f6b029a8f854b22c28b16"
            + "d55d8ff7529d1033ace362824448762400c17e83b10cf95be358d12b4d2040"
            + "49386f628f66754f34ce704f41c4cb1fd7aa50ee349aa12f6c4e255038df1e"
            + "c8f61c08827d1bf5102818100be554151f2fa9f54921db57138ed057dd85c2"
            + "b821eeced055a946f8ffe7a121a698579c80cf65e2d0c962e16072a9f1334b"
            + "0114343c4cca076746674ad61acb73255d393ec38bfa8eee268cf2d1855f5d"
            + "3e2519ed2046afbc343a46ead79fc207921a8667646f43c34190754ad024e1"
            + "af68ede4ae26ad9782c44026869c916ff0281801fa7b994b42cfca59c0a7ef"
            + "1a6b08dd84eb151ad340f76b35ec43ea06e4802e6a671332cede4c4235688e"
            + "5e9edd5f042a4e13f8d428b4f07c3dff6fc88bca9893152c992f424d55330a"
            + "f53f3f8f3e6f6f664e883cec0c6a0dcadce5d9076aed00693a7c637f98d399"
            + "e06fa4be5e498303153c1039a93a2ec530efe30729429c102818100bbc4c3d2"
            + "22d1590a47b403621574cf6c1d5ca0979806c8b5f56c66bb39a417e3f2a1f9"
            + "48807134eb60757035cf101f2b0559854e44b70be069bbdfafcfb4827da0ac"
            + "c7343160b2c3e81778aa9aa45d794d75026c9a683d5aee81f6e031481c91b4"
            + "ae9dc1a781cc44f06898b0d29569947414f1fc126eb2e8395346c4d747c8e5"
            + "028181009bba5aed3cb601c4e8ac3d83a587cfd9b4bd4c9069ff1783229f36"
            + "7f6e3aadc761c45ca846980547654941c49e76825f0729cb726c72d9dbb8b3"
            + "07c458285c7ad92c09c3f6ad13dcafec4d2c69a168174f3a43644f862f787a"
            + "f80a911d32961e7db11ca2c83531d500012e8b9f45aaa46a12b186e3d48f1c"
            + "71463b3d06705dc7";

    // ----------------------------------------------------------------
    // 公共静态字段（类加载时在 static{} 中填充，供 RsaCertController 引用）
    // ----------------------------------------------------------------
    public static PublicKey  rootPublicKey;
    public static PrivateKey rootPrivateKey;
    public static PublicKey  subPublicKey;
    public static PrivateKey subPrivateKey;
    /** Base64 DER 根CA证书 */
    public static String rootCACert;
    /** Base64 DER 子CA证书 */
    public static String subCACert;

    // ----------------------------------------------------------------
    // 静态初始化块：加载根CA密钥 → 生成子CA密钥对 → 签发两张CA证书
    // ----------------------------------------------------------------
    static {
        Security.addProvider(BC);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            rootPublicKey  = kf.generatePublic (new X509EncodedKeySpec(HexUtil.decodeHex(ROOT_PUB_HEX)));
            rootPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(HexUtil.decodeHex(ROOT_PRI_HEX)));

            // 子CA密钥对：每次启动生成（根CA私钥稳定即可保证信任链）
            KeyPair subKp  = generateRsaKeyPair(2048);
            subPublicKey   = subKp.getPublic();
            subPrivateKey  = subKp.getPrivate();

            // 根CA自签证书
            CertCreateDTO rootDto = defaultCaDto("RSA ROOT CA");
            X509Certificate rootCert = buildRootCACert(rootDto);
            rootCACert = Base64.encode(rootCert.getEncoded());

            // 子CA证书（由根CA私钥签）
            CertCreateDTO subDto  = defaultCaDto("RSA SUB CA");
            X500Name      rootDN  = SM2X509CertMaker.buildSubjectDN(rootDto);
            X509Certificate subCert = buildSubCACert(subDto, rootDN);
            subCACert = Base64.encode(subCert.getEncoded());

        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // ----------------------------------------------------------------
    // 公共实例方法（实例本身无额外状态，直接读取 static 字段）
    // ----------------------------------------------------------------

    // ----------------------------------------------------------------
    // 实例字段：默认指向 static CA，T10 起允许覆盖
    // ----------------------------------------------------------------
    private PublicKey  caPublicKey  = subPublicKey;
    private PrivateKey caPrivateKey = subPrivateKey;

    /** T10：使用自建 CA 覆盖默认子 CA 密钥对。 */
    public RSAx509CertMaker withIssuerKeys(PublicKey caPub, PrivateKey caPri) {
        this.caPublicKey  = caPub;
        this.caPrivateKey = caPri;
        return this;
    }

    /**
     * 服务端生成 RSA 密钥对，签发用户证书
     */
    public X509CertificateHolder makeUserCertHolder(KeyPair userKeyPair, CertCreateDTO dto, CertDescInfo descInfo) {
        X500Name issuerDN  = SM2X509CertMaker.buildSubjectDN(descInfo);
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        try {
            Date notBefore = DateUtil.beginOfDay(DateUtil.date());
            Date notAfter  = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
            byte[] csr = CommonUtil.createCSR(subjectDN, userKeyPair.getPublic(), userKeyPair.getPrivate(), SIGN_ALGO).getEncoded();
            // T02: 默认 KeyUsage / EKU，允许 dto 覆盖
            KeyPurposeId[] defaultEku = {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
            KeyUsage defaultUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
            KeyUsage usage = CertExtensionResolver.resolveKeyUsage(dto.getKeyUsages(), defaultUsage);
            KeyPurposeId[] eku = CertExtensionResolver.resolveExtendedKeyUsages(dto.getExtendedKeyUsages(), defaultEku);
            List<GeneralName> sans = CertExtensionResolver.resolveSubjectAltNames(dto.getSubjectAltNames());
            BasicConstraints bc = CertExtensionResolver.resolveBasicConstraints(dto.getBasicConstraintsCA(), null, true);
            return buildUserCertHolder(CertLevel.EndEntity, null, csr, usage, eku, sans, bc, issuerDN, notBefore, notAfter);
        } catch (Exception e) {
            log.error("makeUserCertHolder(KeyPair) failed", e);
        }
        return null;
    }

    /**
     * CSR 方式签发用户证书（私钥由客户端持有）
     */
    public X509CertificateHolder makeUserCertHolder(byte[] csr, CertDescInfo descInfo) {
        return makeUserCertHolder(csr, descInfo, null);
    }

    /**
     * CSR 路径 + 允许 dto 覆盖扩展项（T02）。dto 为 null → 走默认。
     */
    public X509CertificateHolder makeUserCertHolder(byte[] csr, CertDescInfo descInfo, CertCreateDTO dto) {
        X500Name issuerDN = SM2X509CertMaker.buildSubjectDN(descInfo);
        try {
            Date notBefore = DateUtil.beginOfDay(DateUtil.date());
            Date notAfter  = DateUtil.offsetMonth(notBefore, 12);
            KeyPurposeId[] defaultEku = {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
            KeyUsage defaultUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
            KeyUsage usage = dto == null ? defaultUsage
                    : CertExtensionResolver.resolveKeyUsage(dto.getKeyUsages(), defaultUsage);
            KeyPurposeId[] eku = dto == null ? defaultEku
                    : CertExtensionResolver.resolveExtendedKeyUsages(dto.getExtendedKeyUsages(), defaultEku);
            List<GeneralName> sans = dto == null ? new LinkedList<>()
                    : CertExtensionResolver.resolveSubjectAltNames(dto.getSubjectAltNames());
            BasicConstraints bc = CertExtensionResolver.resolveBasicConstraints(
                    dto == null ? null : dto.getBasicConstraintsCA(), null, true);
            return buildUserCertHolder(CertLevel.EndEntity, null, csr, usage, eku, sans, bc, issuerDN, notBefore, notAfter);
        } catch (Exception e) {
            log.error("makeUserCertHolder(csr) failed", e);
        }
        return null;
    }

    // ----------------------------------------------------------------
    // 公共静态工具方法
    // ----------------------------------------------------------------

    public static KeyPair generateRsaKeyPair(int keySize) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BC);
            gen.initialize(keySize, new SecureRandom());
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("generateRsaKeyPair failed", e);
        }
    }

    /** 输出单段 "PRIVATE KEY"（PKCS8）PEM */
    public static byte[] toRsaPriPem(PrivateKey key) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (PemWriter pw = new PemWriter(new OutputStreamWriter(baos))) {
                pw.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
                pw.flush();
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("toRsaPriPem failed", e);
        }
    }

    // ----------------------------------------------------------------
    // 私有 CA 证书构建（仅供静态初始化块调用）
    // ----------------------------------------------------------------

    private static X509Certificate buildRootCACert(CertCreateDTO dto) throws Exception {
        X500Name dn       = SM2X509CertMaker.buildSubjectDN(dto);
        Date notBefore    = DateUtil.beginOfDay(DateUtil.date());
        Date notAfter     = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
        byte[] csr        = CommonUtil.createCSR(dn, rootPublicKey, rootPrivateKey, SIGN_ALGO).getEncoded();
        KeyUsage usage    = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                                        | KeyUsage.keyCertSign    | KeyUsage.cRLSign);
        return buildCACert(CertLevel.RootCA, null, csr, usage, null,
                           dn, dn, notBefore, notAfter, rootPublicKey, rootPrivateKey);
    }

    private static X509Certificate buildSubCACert(CertCreateDTO dto, X500Name issuerDN) throws Exception {
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        Date notBefore     = DateUtil.beginOfDay(DateUtil.date());
        Date notAfter      = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
        byte[] csr         = CommonUtil.createCSR(subjectDN, subPublicKey, subPrivateKey, SIGN_ALGO).getEncoded();
        KeyUsage usage     = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                                         | KeyUsage.keyCertSign    | KeyUsage.cRLSign);
        return buildCACert(CertLevel.SubCA, null, csr, usage, null,
                           subjectDN, issuerDN, notBefore, notAfter, rootPublicKey, rootPrivateKey);
    }

    // ----------------------------------------------------------------
    // 核心低级证书构建（CA 版）
    // ----------------------------------------------------------------

    private static X509Certificate buildCACert(CertLevel certLevel, Integer pathLen,
            byte[] csr, KeyUsage keyUsage, KeyPurposeId[] eku,
            X500Name subjectDN, X500Name issuerDN,
            Date notBefore, Date notAfter,
            PublicKey issPub, PrivateKey issPriv) throws Exception {

        PKCS10CertificationRequest req = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub    = req.getSubjectPublicKeyInfo();

        if (certLevel == CertLevel.RootCA && !issuerDN.equals(subjectDN)) {
            throw new IllegalArgumentException("RootCA: subject must equal issuer");
        }
        if (certLevel == CertLevel.SubCA && issuerDN.equals(subjectDN)) {
            throw new IllegalArgumentException("SubCA: subject must not equal issuer");
        }

        BigInteger serial = randomSerialNumber();
        X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subjectDN, subPub);

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subPub));
        if (certLevel != CertLevel.RootCA) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    ext.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
        }
        BasicConstraints bc = (certLevel == CertLevel.EndEntity) ? new BasicConstraints(false)
                : (pathLen == null ? new BasicConstraints(true) : new BasicConstraints(pathLen));
        builder.addExtension(Extension.basicConstraints, true, bc);
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }

        X509CertificateHolder holder = rsaSign(builder, issPriv);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BC.getName()).getCertificate(holder);
        cert.verify(issPub);
        return cert;
    }

    // ----------------------------------------------------------------
    // 核心低级证书构建（用户证书版）
    // ----------------------------------------------------------------

    private X509CertificateHolder buildUserCertHolder(CertLevel certLevel, Integer pathLen,
            byte[] csr, KeyUsage keyUsage, KeyPurposeId[] eku,
            List<GeneralName> customSans, BasicConstraints bcOverride,
            X500Name issuerDN, Date notBefore, Date notAfter) throws Exception {

        PKCS10CertificationRequest req = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub    = req.getSubjectPublicKeyInfo();
        X500Name subject               = req.getSubject();

        List<GeneralName> subjectAltNames = new LinkedList<>();
        if (customSans != null && !customSans.isEmpty()) {
            subjectAltNames.addAll(customSans);
        }

        BigInteger serial = randomSerialNumber();
        X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subject, subPub);

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(caPublicKey.getEncoded())));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subPub));
        BasicConstraints bc = bcOverride != null ? bcOverride : new BasicConstraints(false);
        builder.addExtension(Extension.basicConstraints, false, bc);
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }
        if (!subjectAltNames.isEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }
        return rsaSign(builder, caPrivateKey);
    }

    private static X509CertificateHolder rsaSign(X509v3CertificateBuilder builder, PrivateKey priv)
            throws OperatorCreationException {
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGO)
                .setProvider(BC.getName()).build(priv);
        return builder.build(signer);
    }


    private static BigInteger randomSerialNumber() {
        byte[] bytes = new byte[16];
        SERIAL_RANDOM.nextBytes(bytes);
        bytes[0] &= 0x7F;
        return new BigInteger(1, bytes);
    }

    // ----------------------------------------------------------------
    // 默认 CA DTO（供静态初始化块使用）
    // ----------------------------------------------------------------

    private static CertCreateDTO defaultCaDto(String cn) {
        CertCreateDTO dto = new CertCreateDTO();
        dto.setDn_cn(cn);
        dto.setDn_c("CN");
        dto.setDn_st("DEMO");
        dto.setDn_l("DEMO");
        dto.setDn_street("DEMO");
        dto.setDn_email("demo@example.com");
        dto.setDn_o("OPEN-GM-JCA DEMO");
        dto.setDn_ou("DEMO CA");
        dto.setCertValidMonth(240);
        dto.setP12Password(PASSWORD);
        return dto;
    }
}
