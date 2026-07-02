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

import lombok.extern.slf4j.Slf4j;
import cn.hutool.core.codec.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

@Slf4j
public class CommonUtil {
    /**
     * 如果不知道怎么填充names，可以查看org.bouncycastle.asn1.x500.style.BCStyle这个类，
     * names的key值必须是BCStyle.DefaultLookUp中存在的（可以不关心大小写）
     *
     * @param names
     * @return
     */
    public static X500Name buildX500Name(Map<String, String> names) throws RuntimeException {
        if (names == null || names.size() == 0) {
            throw new RuntimeException("names can not be empty");
        }
        try {
            X500NameBuilder builder = new X500NameBuilder();
            Iterator itr = names.entrySet().iterator();
            BCStyle x500NameStyle = (BCStyle) BCStyle.INSTANCE;
            Map.Entry entry;
            while (itr.hasNext()) {
                entry = (Map.Entry) itr.next();
                ASN1ObjectIdentifier oid = x500NameStyle.attrNameToOID((String) entry.getKey());
                builder.addRDN(oid, (String) entry.getValue());
            }
            return builder.build();
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static PKCS10CertificationRequest createCSR(X500Name subject, PublicKey pubKey, PrivateKey priKey,
                                                       String signAlgo) throws OperatorCreationException {
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
        ContentSigner signerBuilder = new JcaContentSignerBuilder(signAlgo)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(priKey);
        return csrBuilder.build(signerBuilder);
    }

    public static AlgorithmIdentifier findSignatureAlgorithmIdentifier(String algoName) {
        DefaultSignatureAlgorithmIdentifierFinder sigFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        return sigFinder.find(algoName);
    }

    public static AlgorithmIdentifier findDigestAlgorithmIdentifier(String algoName) {
        DefaultDigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        return digFinder.find(findSignatureAlgorithmIdentifier(algoName));
    }

    public static void main(String[] args) throws Exception {
        String publicStr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADc3mK3GpOAUVMkDwABQ/P9/SxZllAu103sXN" +
                "/iqPli0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAER+GnzyG7DAEkC28M5yLyU504Nd1tiQ28iqGNb0Z+E4=";
        PublicKey issuerPublicKey = convertBytesToPublicKey(publicStr);

    }

    // public static PublicKey



    private static byte[] convertHardPublicKeyToSoftPublicKey(byte[] hardPublicKey) {
        System.out.println("hardPublicKey:\n" + Arrays.toString(hardPublicKey));
        byte[] xByte = subbytes(hardPublicKey, 0, 64);
        System.out.println("xByte:\n" + Arrays.toString(xByte));
        System.out.println("xByte.length:" + xByte.length);
        byte[] yByte = subbytes(hardPublicKey, 64, 128);
        System.out.println("yByte:\n" + Arrays.toString(yByte));
        System.out.println("yByte.length:" + yByte.length);
        ECPublicKeyParameters ecPublicKeyParameters =  BCECUtil.createECPublicKeyParameters(
                xByte, yByte, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);
        return BCECUtil.convertECPublicKeyToX509(ecPublicKeyParameters);
    }


    /**
     * 简单的混淆md5字符串
     * 遍历一个字符串，将其中的第一次遍历到的a字符改成b，第一次遍历到的e字符改成0
     *
     * @param md5Str md5字符串，
     * @return String
     */
    public static String confuseMd5(String md5Str) {
        char[] chars = md5Str.toCharArray();
        boolean firstA = true;
        boolean firstE = true;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == 'a' && firstA) {
                chars[i] = 'b';
                firstA = false;
            } else if (chars[i] == 'e' && firstE) {
                chars[i] = '0';
                firstE = false;
            }
        }
        return new String(chars);
    }

    public static PublicKey convertBytesToPublicKeyByQm(String puck) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            byte[] hardPublicKey = Base64.decode(puck);
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            byte[] x = new byte[64];
            byte[] y = new byte[64];
            System.arraycopy(hardPublicKey, 4, x, 0, 64);
            int pos = 4 + x.length;
            System.arraycopy(hardPublicKey, pos, y, 0, 64);
            BigInteger xCoord = new BigInteger(1, x);
            BigInteger yCoord = new BigInteger(1, y);
            org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(parameterSpec.getCurve().createPoint(xCoord, yCoord), parameterSpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return publicKey;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            // ResultAssert.throwFail(GenerateCertApiCode.SELF_CA_HARDWARE_PUBLIC_KEY_DATA_ERROR);
        }
        return null;
    }

    public static PublicKey convertBytesToPublicKey(String publicStr) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            byte[] hardPublicKey = Base64.decode(publicStr);
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            System.out.println("hardPublicKey:\n" + Arrays.toString(hardPublicKey));
            byte[] xByte = subbytes(hardPublicKey, 0, 64);
            System.out.println("xByte:\n" + Arrays.toString(xByte));
            System.out.println("xByte.length:" + xByte.length);
            byte[] yByte = subbytes(hardPublicKey, 64, 64);
            System.out.println("yByte:\n" + Arrays.toString(yByte));
            System.out.println("yByte.length:" + yByte.length);
            BigInteger xCoord = new BigInteger(1, xByte);
            BigInteger yCoord = new BigInteger(1, yByte);
            System.out.println("xCoord:\n" + Arrays.toString(xCoord.toByteArray()));
            org.bouncycastle.jce.spec.ECPublicKeySpec publicKeySpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(parameterSpec.getCurve().createPoint(xCoord, yCoord), parameterSpec);
            return (BCECPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            log.error(e.getMessage(),e);
            // ResultAssert.throwFail(GenerateCertApiCode.SELF_CA_HARDWARE_PUBLIC_KEY_DATA_ERROR);
        }
        return null;
    }

    /**
     * 分割byte
     * @param bytes 源
     * @param srcPos 起始位置
     * @param length 长度
     * @return
     */
    public static byte[] subbytes(byte[] bytes, int srcPos, int length) {
        byte[] buf = new byte[length];
        System.arraycopy(bytes, srcPos, buf, 0, length);
        return buf;
    }

    /**
     * 合并byte
     * @param byte1
     * @param byte2
     * @return
     */
    public static byte[] combineBytes(byte[] byte1, byte[] byte2) {
        byte[] result = new byte[byte1.length + byte2.length];
        System.arraycopy(byte1, 0, result, 0, byte1.length);
        System.arraycopy(byte2, 0, result, byte1.length, byte2.length);
        return result;
    }
}
