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

import cn.hutool.core.codec.Base64;
import cn.hutool.core.text.StrPool;
import cn.hutool.core.util.ObjectUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.util.List;

@Slf4j
public class SM2CertUtil {
    public static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bcProvider);
    }

    public static BCECPublicKey getBCECPublicKey(X509Certificate sm2Cert) {
        ECPublicKey pubKey = (ECPublicKey) sm2Cert.getPublicKey();
        ECPoint q = pubKey.getQ();
        ECParameterSpec parameterSpec = new ECParameterSpec(SM2Util.CURVE, SM2Util.G_POINT, SM2Util.SM2_ECC_N, SM2Util.SM2_ECC_H);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, parameterSpec);
        return new BCECPublicKey(pubKey.getAlgorithm(), pubKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 校验证书
     *
     * @param issuerPubKey 从颁发者CA证书中提取出来的公钥
     * @param cert         待校验的证书
     * @return
     */
    public static boolean verifyCertificate(BCECPublicKey issuerPubKey, X509Certificate cert) {
        try {
            cert.verify(issuerPubKey, bcProvider);
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    public static X509Certificate getX509Certificate(
            String certFilePath) throws IOException, CertificateException, NoSuchProviderException {
        InputStream is = null;
        try {
            is = new FileInputStream(certFilePath);
            return getX509Certificate(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    public static X509Certificate getX509Certificate(byte[] certBytes) throws CertificateException, NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
        return getX509Certificate(bais);
    }

    public static X509Certificate getX509Certificate(InputStream is) throws CertificateException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bcProvider);
        return (X509Certificate) cf.generateCertificate(is);
    }

    public static CertPath getCertificateChain(String certChainPath) throws IOException, CertificateException, NoSuchProviderException {
        InputStream is = null;
        try {
            is = new FileInputStream(certChainPath);
            return getCertificateChain(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    public static CertPath getCertificateChain(byte[] certChainBytes) throws CertificateException, NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certChainBytes);
        return getCertificateChain(bais);
    }

    public static byte[] getCertificateChainBytes(CertPath certChain) throws CertificateEncodingException {
        return certChain.getEncoded("PKCS7");
    }

    public static CertPath getCertificateChain(InputStream is) throws CertificateException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return cf.generateCertPath(is, "PKCS7");
    }

    public static CertPath getCertificateChain(List<X509Certificate> certs) throws CertificateException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return cf.generateCertPath(certs);
    }

    public static X509Certificate getX509CertificateFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                X509CertificateHolder certHolder = (X509CertificateHolder) bags[0].getBagValue();
                return SM2CertUtil.getX509Certificate(certHolder.getEncoded());
            }
        }

        throw new Exception("Not found X509Certificate in this pfx");
    }

    public static BCECPublicKey getPublicKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        return SM2CertUtil.getBCECPublicKey(getX509CertificateFromPfx(pfxDER, passwd));
    }

    public static BCECPrivateKey getPrivateKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (!infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo) bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
                BCECPrivateKey privateKey = BCECUtil.convertPKCS8ToECPrivateKey(info.getEncoded());
                return privateKey;
            }
        }

        throw new Exception("Not found Private Key in this pfx");
    }

    // 将X509证书转换为PEM格式，并返回byte[]
    public static byte[] convertToPem(X509Certificate certificate) throws IOException, CertificateEncodingException {
        return convertToPem(certificate.getEncoded());
    }

    public static byte[] convertToPem(String base64CertStr) throws IOException {
        return convertToPem(Base64.decode(base64CertStr));
    }

    public static byte[] convertToPem(byte[] certBytes) throws IOException {
        // 创建一个ByteArrayOutputStream来捕获PEM内容
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        // 使用JcaPEMWriter将证书写入ByteArrayOutputStream
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(byteArrayOutputStream))) {
            PemObject pemObject = new PemObject("CERTIFICATE", certBytes);
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
        }
        // 将ByteArrayOutputStream转换为byte[]并返回
        return byteArrayOutputStream.toByteArray();
    }

    public static X509Certificate convertToX509Certificate(String base64CertStr) {
        return convertToX509Certificate(Base64.decode(base64CertStr));
    }

    public static X509Certificate convertToX509Certificate(byte[] certBytes) {
        try {
            InputStream inputStream = new ByteArrayInputStream(certBytes);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", bcProvider);
            return (X509Certificate) cf.generateCertificate(inputStream);
        } catch (Exception e) {
            log.error("证书转换失败", e);
        }
        throw new IllegalArgumentException("证书转换失败");
    }

    public static String getUniversalName(X500Name x500Name) {
        try {
            if (ObjectUtil.isNotNull(x500Name)) {
                return getDnItemValue(x500Name.toString(), "CN");
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        throw new IllegalArgumentException("证书可识别名解析失败");
    }

    public static String getDnItemValue(String dn, final String itemName) {
        if (StringUtils.isBlank(dn) || StringUtils.isBlank(itemName)) {
            return null;
        }

        String[] items = dn.split(StrPool.COMMA);
        for (String item : items) {
            String[] itemArray = item.split("=");
            if (itemArray.length != 2) {
                throw new IllegalArgumentException("parse dn fail with wrong format");
            }
            if (itemName.equalsIgnoreCase(itemArray[0])) {
                return itemArray[1];
            }
        }
        return null;
    }
}
