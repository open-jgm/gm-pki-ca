package com.open.jgm.pki.ca.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * 无外部依赖，纯 main 方法生成 SM2 CSR PEM 字符串。
 * <p>
 * 运行方式：
 * <pre>
 *   JAVA_HOME="/c/Users/16483/.jdks/ms-17.0.18" mvn -Dtest=GenerateCSRMainTest test
 * </pre>
 * 或直接 IDE 右键运行 main。
 */
public class GenerateCSRMainTest {

    public static void main(String[] args) throws Exception {
        // 1. 注册 BC Provider
        Security.addProvider(new BouncyCastleProvider());

        // 2. 构造 Subject DN（按需修改）
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "张三")
                .addRDN(BCStyle.C,  "CN")
                .addRDN(BCStyle.ST, "DEMO")
                .addRDN(BCStyle.L,  "DEMO")
                .addRDN(BCStyle.O,  "openCA")
                .addRDN(BCStyle.OU, "dev")
                .build();

        // 3. 生成 SM2 密钥对
        ECNamedCurveParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(sm2Spec);
        KeyPair keyPair = kpg.generateKeyPair();

        // 4. 生成 PKCS#10 CSR（SM3withSM2 签名）
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        PKCS10CertificationRequest csr = csrBuilder.build(
                new JcaContentSignerBuilder("SM3withSM2")
                        .setProvider("BC")
                        .build(keyPair.getPrivate()));

        // 5. 输出 PEM 字符串
        String csrPem = toPemString("CERTIFICATE REQUEST", csr.getEncoded());
        String keyPem = toPemString("PRIVATE KEY", keyPair.getPrivate().getEncoded());

        System.out.println("===== CSR PEM =====");
        System.out.print(csrPem);
        System.out.println("===== PRIVATE KEY PEM =====");
        System.out.print(keyPem);
    }

    private static String toPemString(String type, byte[] content) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject(type, content));
        }
        return sw.toString();
    }
}
