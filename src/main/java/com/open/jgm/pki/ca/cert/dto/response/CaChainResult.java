package com.open.jgm.pki.ca.cert.dto.response;

import lombok.Value;

/**
 * CA 证书链数据（替代 CertCADTO）。
 */
@Value
public class CaChainResult {

    byte[] rcaBytes;
    byte[] rcaPemBytes;
    byte[] ocaBytes;
    byte[] ocaPemBytes;
    /** rca.pem + oca.pem 合并（trust.pem） */
    byte[] trustPemBytes;
    byte[] p7bBytes;
}
