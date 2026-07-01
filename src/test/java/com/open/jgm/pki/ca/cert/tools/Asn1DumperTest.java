package com.open.jgm.pki.ca.cert.tools;

import cn.hutool.core.codec.Base64;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.cert.exception.CertException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * T28：ASN.1 dumper 测试。
 */
class Asn1DumperTest {

    @Test
    void dumpsSimpleSequence() throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(42));
        v.add(new DERUTF8String("hello"));
        v.add(new ASN1ObjectIdentifier("1.2.3.4"));
        byte[] der = new DERSequence(v).getEncoded();

        String out = Asn1Dumper.dump(der);

        assertThat(out).contains("SEQUENCE (3)");
        assertThat(out).contains("INTEGER 42");
        assertThat(out).contains("\"hello\"");
        assertThat(out).contains("OID 1.2.3.4");
    }

    @Test
    void dumpsBuiltinSm2CaCert() {
        byte[] der = Base64.decode(SM2X509CertMaker.subCACert);
        String out = Asn1Dumper.dump(der);
        assertThat(out).startsWith("SEQUENCE");
        // 证书结构必定包含序列号 INTEGER 和签名 BIT STRING
        assertThat(out).contains("INTEGER");
        assertThat(out).contains("BIT STRING");
    }

    @Test
    void emptyInputThrows() {
        assertThatThrownBy(() -> Asn1Dumper.dump(new byte[0]))
                .isInstanceOf(CertException.class);
    }
}
