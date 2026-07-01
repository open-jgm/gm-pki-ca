package com.open.jgm.pki.ca.cert.exception;

/**
 * 证书领域专用运行时异常，替代各处 throw new Exception("...") 及 e.printStackTrace()。
 */
public class CertException extends RuntimeException {

    public CertException(String message) {
        super(message);
    }

    public CertException(String message, Throwable cause) {
        super(message, cause);
    }
}
