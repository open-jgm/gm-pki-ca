package com.open.jgm.pki.ca.cert.envelope;

import com.open.jgm.pki.ca.cert.crypto.SM2Util;
import com.open.jgm.pki.ca.cert.crypto.Sm4Util;
import com.open.jgm.pki.ca.cert.exception.CertException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * T17-T19：数字信封服务。
 * <p>
 * 信封结构（自定义 ASN.1，与 PKCS#7 EnvelopedData 同构，便于互操作）：
 * <pre>
 * GmEnvelope ::= SEQUENCE {
 *     version              INTEGER (1),
 *     contentEncryption    AlgorithmIdentifier,    -- SM4-CBC 或 AES-128-CBC
 *     iv                   OCTET STRING,
 *     recipientInfos       SET OF RecipientInfo,
 *     encryptedContent     OCTET STRING
 * }
 * RecipientInfo ::= SEQUENCE {
 *     version              INTEGER (1),
 *     keyEncryption        AlgorithmIdentifier,    -- SM2 或 RSA
 *     issuer               Name,
 *     serialNumber         INTEGER,
 *     encryptedKey         OCTET STRING            -- SM2 输出为 C1C3C2 字节流；RSA 输出 PKCS1 v1.5 密文
 * }
 * </pre>
 * <p>
 * 算法选择：
 * <ul>
 *   <li>收件人证书算法为 SM2（EC + SM2P256V1 曲线） → 内容加密用 SM4-CBC，密钥包用 SM2-Encrypt</li>
 *   <li>收件人证书算法为 RSA → 内容加密用 AES-128-CBC，密钥包用 RSA/ECB/PKCS1Padding</li>
 * </ul>
 * <b>互操作说明：</b>本结构遵循 GM/T 0010-2012 思路但简化了字段；未与商业 GmSSL/openssl
 * 的标准 envelopedData 做严格 OID/CMS 包装对齐。完整 PKCS7 标准信封留待后续迭代扩展。
 */
@Service
@Slf4j
public class EnvelopeService {

    private static final int ENVELOPE_VERSION = 1;

    // ──────────────────────────────────────────────────────────
    // T17：加密
    // ──────────────────────────────────────────────────────────

    /**
     * 用收件人证书的公钥加密任意明文，输出信封 DER 字节。
     */
    public byte[] encrypt(byte[] plain, X509Certificate recipientCert) {
        if (plain == null) {
            throw new CertException("明文不能为空");
        }
        if (recipientCert == null) {
            throw new CertException("收件人证书不能为空");
        }
        try {
            PublicKey pub = recipientCert.getPublicKey();
            CryptoSuite suite = pickSuite(pub);

            byte[] iv = Sm4Util.generateIv();
            byte[] sessionKey = suite.generateContentKey();
            byte[] ciphertext = suite.encryptContent(sessionKey, iv, plain);
            byte[] wrappedKey = suite.wrapKey(pub, sessionKey);

            return buildEnvelope(
                    suite.contentEncryptionOid(),
                    iv,
                    ciphertext,
                    List.of(new RecipientEntry(recipientCert, suite.keyEncryptionOid(), wrappedKey)));
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("信封加密失败", e);
            throw new CertException("信封加密失败: " + e.getMessage(), e);
        }
    }

    // ──────────────────────────────────────────────────────────
    // T18：解密
    // ──────────────────────────────────────────────────────────

    /**
     * 用私钥与对应证书解开信封；证书用于匹配 recipientInfo 中的 issuer/serial。
     */
    public byte[] decrypt(byte[] envelopeDer, PrivateKey privateKey, X509Certificate ownerCert) {
        if (envelopeDer == null || envelopeDer.length == 0) {
            throw new CertException("信封字节不能为空");
        }
        if (privateKey == null) {
            throw new CertException("私钥不能为空");
        }
        try {
            ParsedEnvelope p = parseAsn1(envelopeDer);
            CryptoSuite suite = suiteFor(p.contentEncryptionOid, privateKey);

            byte[] encryptedKey = matchRecipient(p, ownerCert, suite);
            byte[] sessionKey = suite.unwrapKey(privateKey, encryptedKey);
            return suite.decryptContent(sessionKey, p.iv, p.ciphertext);
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            log.error("信封解密失败", e);
            throw new CertException("信封解密失败: " + e.getMessage(), e);
        }
    }

    // ──────────────────────────────────────────────────────────
    // T19：解析（不解密）
    // ──────────────────────────────────────────────────────────

    public EnvelopeInfo parse(byte[] envelopeDer) {
        if (envelopeDer == null || envelopeDer.length == 0) {
            throw new CertException("信封字节不能为空");
        }
        ParsedEnvelope p = parseAsn1(envelopeDer);
        return EnvelopeInfo.builder()
                .version(p.version)
                .contentEncryptionAlgorithmOid(p.contentEncryptionOid.getId())
                .contentEncryptionAlgorithmName(algoDisplayName(p.contentEncryptionOid))
                .encryptedContentLength(p.ciphertext.length)
                .ivLength(p.iv.length)
                .recipients(p.recipients.stream().map(r -> EnvelopeInfo.RecipientView.builder()
                        .issuer(r.issuer.toString())
                        .serialNumberHex(r.serialNumber.toString(16))
                        .keyEncryptionAlgorithmOid(r.keyEncryptionOid.getId())
                        .keyEncryptionAlgorithmName(algoDisplayName(r.keyEncryptionOid))
                        .encryptedKeyLength(r.encryptedKey.length)
                        .build()).toList())
                .build();
    }

    // ──────────────────────────────────────────────────────────
    // ASN.1 编码
    // ──────────────────────────────────────────────────────────

    private static byte[] buildEnvelope(ASN1ObjectIdentifier contentEnc,
                                        byte[] iv,
                                        byte[] ciphertext,
                                        List<RecipientEntry> recipients) throws IOException {
        ASN1EncodableVector recVec = new ASN1EncodableVector();
        for (RecipientEntry r : recipients) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(ENVELOPE_VERSION));
            v.add(new AlgorithmIdentifier(r.keyEncryptionOid));
            v.add(X500Name.getInstance(r.cert.getIssuerX500Principal().getEncoded()));
            v.add(new ASN1Integer(r.cert.getSerialNumber()));
            v.add(new DEROctetString(r.encryptedKey));
            recVec.add(new DERSequence(v));
        }

        ASN1EncodableVector top = new ASN1EncodableVector();
        top.add(new ASN1Integer(ENVELOPE_VERSION));
        top.add(new AlgorithmIdentifier(contentEnc));
        top.add(new DEROctetString(iv));
        top.add(new DERSet(recVec));
        top.add(new DEROctetString(ciphertext));
        return new DERSequence(top).getEncoded(ASN1Encoding.DER);
    }

    private static ParsedEnvelope parseAsn1(byte[] envelopeDer) {
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(envelopeDer))) {
            ASN1Sequence seq = ASN1Sequence.getInstance(in.readObject());
            if (seq.size() != 5) {
                throw new CertException("信封 ASN.1 字段数错误，期望 5，实际 " + seq.size());
            }
            int version = ((ASN1Integer) seq.getObjectAt(0)).getValue().intValueExact();
            AlgorithmIdentifier ai = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            byte[] iv = ((DEROctetString) seq.getObjectAt(2)).getOctets();
            ASN1Set recSet = ASN1Set.getInstance(seq.getObjectAt(3));
            byte[] ct = ((DEROctetString) seq.getObjectAt(4)).getOctets();

            List<ParsedRecipient> rs = new ArrayList<>(recSet.size());
            for (int i = 0; i < recSet.size(); i++) {
                ASN1Sequence rseq = ASN1Sequence.getInstance(recSet.getObjectAt(i));
                if (rseq.size() != 5) {
                    throw new CertException("RecipientInfo 字段数错误，期望 5，实际 " + rseq.size());
                }
                int rv = ((ASN1Integer) rseq.getObjectAt(0)).getValue().intValueExact();
                AlgorithmIdentifier kai = AlgorithmIdentifier.getInstance(rseq.getObjectAt(1));
                X500Name issuer = X500Name.getInstance(rseq.getObjectAt(2));
                BigInteger serial = ((ASN1Integer) rseq.getObjectAt(3)).getValue();
                byte[] ek = ((DEROctetString) rseq.getObjectAt(4)).getOctets();
                rs.add(new ParsedRecipient(rv, kai.getAlgorithm(), issuer, serial, ek));
            }

            return new ParsedEnvelope(version, ai.getAlgorithm(), iv, ct, rs);
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("信封 ASN.1 解析失败: " + e.getMessage(), e);
        }
    }

    private static byte[] matchRecipient(ParsedEnvelope p, X509Certificate ownerCert, CryptoSuite suite) {
        for (ParsedRecipient r : p.recipients) {
            if (!suite.keyEncryptionOid().equals(r.keyEncryptionOid)) {
                continue;
            }
            if (ownerCert != null) {
                X500Name expectedIssuer = X500Name.getInstance(ownerCert.getIssuerX500Principal().getEncoded());
                if (!r.issuer.equals(expectedIssuer)) continue;
                if (!r.serialNumber.equals(ownerCert.getSerialNumber())) continue;
                return r.encryptedKey;
            }
            // 未提供 ownerCert：取第一个算法匹配的 recipient
            return r.encryptedKey;
        }
        throw new CertException("信封中没有匹配的 RecipientInfo（owner 证书的 issuer/serial 不一致）");
    }

    // ──────────────────────────────────────────────────────────
    // 算法套件抽象
    // ──────────────────────────────────────────────────────────

    private static CryptoSuite pickSuite(PublicKey pub) {
        if (pub instanceof BCECPublicKey) {
            return new Sm2Sm4Suite();
        }
        if ("RSA".equalsIgnoreCase(pub.getAlgorithm())) {
            return new RsaAesSuite();
        }
        throw new CertException("不支持的收件人证书算法: " + pub.getAlgorithm());
    }

    private static CryptoSuite suiteFor(ASN1ObjectIdentifier contentEncOid, PrivateKey privateKey) {
        if (GmEnvelopeOids.SM4_CBC.equals(contentEncOid)) {
            if (!(privateKey instanceof BCECPrivateKey)) {
                throw new CertException("信封声明 SM4-CBC，但私钥不是 EC 私钥");
            }
            return new Sm2Sm4Suite();
        }
        if (GmEnvelopeOids.AES_128_CBC.equals(contentEncOid)) {
            if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
                throw new CertException("信封声明 AES-128-CBC，但私钥不是 RSA 私钥");
            }
            return new RsaAesSuite();
        }
        throw new CertException("不支持的内容加密算法 OID: " + contentEncOid.getId());
    }

    /** 加密 / 解密 / 包装 / 解包套件。 */
    interface CryptoSuite {
        ASN1ObjectIdentifier contentEncryptionOid();
        ASN1ObjectIdentifier keyEncryptionOid();
        byte[] generateContentKey();
        byte[] encryptContent(byte[] key, byte[] iv, byte[] plain) throws Exception;
        byte[] decryptContent(byte[] key, byte[] iv, byte[] ciphertext) throws Exception;
        byte[] wrapKey(PublicKey pub, byte[] sessionKey) throws Exception;
        byte[] unwrapKey(PrivateKey priv, byte[] wrapped) throws Exception;
    }

    /** SM2 + SM4 套件（国密推荐组合）。 */
    private static final class Sm2Sm4Suite implements CryptoSuite {
        @Override public ASN1ObjectIdentifier contentEncryptionOid() { return GmEnvelopeOids.SM4_CBC; }
        @Override public ASN1ObjectIdentifier keyEncryptionOid()     { return GmEnvelopeOids.SM2_ENCRYPT; }
        @Override public byte[] generateContentKey()                  { return Sm4Util.generateKey(); }
        @Override public byte[] encryptContent(byte[] key, byte[] iv, byte[] plain) {
            return Sm4Util.encryptWithIv(key, iv, plain);
        }
        @Override public byte[] decryptContent(byte[] key, byte[] iv, byte[] ciphertext) {
            return Sm4Util.decryptWithIv(key, iv, ciphertext);
        }
        @Override public byte[] wrapKey(PublicKey pub, byte[] sessionKey) throws Exception {
            return SM2Util.encrypt((BCECPublicKey) pub, sessionKey);
        }
        @Override public byte[] unwrapKey(PrivateKey priv, byte[] wrapped) throws Exception {
            return SM2Util.decrypt((BCECPrivateKey) priv, wrapped);
        }
    }

    /** RSA + AES-128-CBC 套件（国际通用组合）。 */
    private static final class RsaAesSuite implements CryptoSuite {
        @Override public ASN1ObjectIdentifier contentEncryptionOid() { return GmEnvelopeOids.AES_128_CBC; }
        @Override public ASN1ObjectIdentifier keyEncryptionOid()     { return GmEnvelopeOids.RSA_PKCS1; }
        @Override public byte[] generateContentKey() {
            byte[] k = new byte[16];
            new java.security.SecureRandom().nextBytes(k);
            return k;
        }
        @Override public byte[] encryptContent(byte[] key, byte[] iv, byte[] plain) throws Exception {
            return aesCbc(Cipher.ENCRYPT_MODE, key, iv, plain);
        }
        @Override public byte[] decryptContent(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
            return aesCbc(Cipher.DECRYPT_MODE, key, iv, ciphertext);
        }
        @Override public byte[] wrapKey(PublicKey pub, byte[] sessionKey) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, pub);
            return c.doFinal(sessionKey);
        }
        @Override public byte[] unwrapKey(PrivateKey priv, byte[] wrapped) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.DECRYPT_MODE, priv);
            return c.doFinal(wrapped);
        }
        private static byte[] aesCbc(int mode, byte[] key, byte[] iv, byte[] input) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(mode,
                    new javax.crypto.spec.SecretKeySpec(key, "AES"),
                    new javax.crypto.spec.IvParameterSpec(iv));
            return cipher.doFinal(input);
        }
    }

    private static String algoDisplayName(ASN1ObjectIdentifier oid) {
        if (GmEnvelopeOids.SM4_CBC.equals(oid)) return "SM4-CBC";
        if (GmEnvelopeOids.SM2_ENCRYPT.equals(oid)) return "SM2-Encrypt";
        if (GmEnvelopeOids.RSA_PKCS1.equals(oid)) return "RSA-PKCS1-v1_5";
        if (GmEnvelopeOids.AES_128_CBC.equals(oid)) return "AES-128-CBC";
        return oid.getId();
    }

    // ──────────────────────────────────────────────────────────
    // 内部值类型
    // ──────────────────────────────────────────────────────────

    private record RecipientEntry(X509Certificate cert, ASN1ObjectIdentifier keyEncryptionOid, byte[] encryptedKey) {}

    private record ParsedEnvelope(int version,
                                   ASN1ObjectIdentifier contentEncryptionOid,
                                   byte[] iv,
                                   byte[] ciphertext,
                                   List<ParsedRecipient> recipients) {}

    private record ParsedRecipient(int version,
                                    ASN1ObjectIdentifier keyEncryptionOid,
                                    X500Name issuer,
                                    BigInteger serialNumber,
                                    byte[] encryptedKey) {}
}
