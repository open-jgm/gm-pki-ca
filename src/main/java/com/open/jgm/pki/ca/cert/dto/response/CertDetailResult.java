package com.open.jgm.pki.ca.cert.dto.response;

import lombok.Data;

import java.util.Date;

/**
 * 证书可读信息（替代 CertDescInfo）。
 */
@Data
public class CertDetailResult {

    private String universalName;
    private String organization;
    private String organizationUnit;
    private String country;
    private String province;
    private String city;
    private String street;
    private String email;
    private String issueOrg;
    private String cert;
    private String serialNumberHex;
    private Date certValidStartTime;
    private Date certValidEndTime;

    // T22：v3 扩展项
    private String signatureAlgorithm;
    private String publicKeyAlgorithm;
    private Integer publicKeyBits;
    private CertExtensionsView extensions;
}
