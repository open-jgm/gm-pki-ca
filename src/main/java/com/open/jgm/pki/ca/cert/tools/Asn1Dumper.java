package com.open.jgm.pki.ca.cert.tools;

import com.open.jgm.pki.ca.cert.exception.CertException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.ByteArrayInputStream;

/**
 * T28：把 ASN.1 DER 字节流转成树形文本（类似 openssl asn1parse）。
 */
public final class Asn1Dumper {

    private static final int MAX_OCTET_PREVIEW = 64;

    private Asn1Dumper() {}

    public static String dump(byte[] der) {
        if (der == null || der.length == 0) {
            throw new CertException("input 不能为空");
        }
        StringBuilder sb = new StringBuilder();
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
            ASN1Primitive obj;
            while ((obj = in.readObject()) != null) {
                writeNode(sb, obj, 0);
            }
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("ASN.1 解析失败: " + e.getMessage(), e);
        }
        return sb.toString();
    }

    private static void writeNode(StringBuilder sb, ASN1Encodable enc, int depth) {
        indent(sb, depth);
        ASN1Primitive prim = enc.toASN1Primitive();
        if (prim instanceof ASN1Sequence seq) {
            sb.append("SEQUENCE (").append(seq.size()).append(")\n");
            for (int i = 0; i < seq.size(); i++) writeNode(sb, seq.getObjectAt(i), depth + 1);
            return;
        }
        if (prim instanceof ASN1Set set) {
            sb.append("SET (").append(set.size()).append(")\n");
            for (int i = 0; i < set.size(); i++) writeNode(sb, set.getObjectAt(i), depth + 1);
            return;
        }
        if (prim instanceof ASN1TaggedObject tag) {
            sb.append("[").append(tag.getTagNo()).append("]");
            sb.append(" (explicit=").append(tag.isExplicit()).append(")\n");
            writeNode(sb, tag.getBaseObject(), depth + 1);
            return;
        }
        if (prim instanceof ASN1ObjectIdentifier oid) {
            sb.append("OID ").append(oid.getId()).append('\n');
            return;
        }
        if (prim instanceof ASN1Integer i) {
            sb.append("INTEGER ").append(i.getValue()).append('\n');
            return;
        }
        if (prim instanceof ASN1Boolean b) {
            sb.append("BOOLEAN ").append(b.isTrue()).append('\n');
            return;
        }
        if (prim instanceof ASN1Null) {
            sb.append("NULL\n");
            return;
        }
        if (prim instanceof ASN1Enumerated e) {
            sb.append("ENUMERATED ").append(e.getValue()).append('\n');
            return;
        }
        if (prim instanceof ASN1OctetString os) {
            byte[] octets = os.getOctets();
            sb.append("OCTET STRING (").append(octets.length).append(") ").append(hexPreview(octets)).append('\n');
            // 尝试递归解析（DER-in-OCTET 常见）
            try (ASN1InputStream nested = new ASN1InputStream(new ByteArrayInputStream(octets))) {
                ASN1Primitive inner;
                while ((inner = nested.readObject()) != null) writeNode(sb, inner, depth + 1);
            } catch (Exception ignored) {
                // not nested ASN.1 — leave as raw
            }
            return;
        }
        if (prim instanceof ASN1BitString bs) {
            byte[] bytes = bs.getBytes();
            sb.append("BIT STRING (").append(bytes.length * 8 - bs.getPadBits()).append(" bits) ")
                    .append(hexPreview(bytes)).append('\n');
            return;
        }
        if (prim instanceof ASN1String s) {
            sb.append(prim.getClass().getSimpleName()).append(' ').append('"').append(s.getString()).append('"').append('\n');
            return;
        }
        sb.append(prim.getClass().getSimpleName()).append('\n');
    }

    private static String hexPreview(byte[] bytes) {
        int n = Math.min(MAX_OCTET_PREVIEW, bytes.length);
        StringBuilder hex = new StringBuilder(n * 2 + 4);
        hex.append("0x");
        for (int i = 0; i < n; i++) hex.append(String.format("%02x", bytes[i]));
        if (bytes.length > MAX_OCTET_PREVIEW) hex.append("...");
        return hex.toString();
    }

    private static void indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) sb.append("  ");
    }
}
