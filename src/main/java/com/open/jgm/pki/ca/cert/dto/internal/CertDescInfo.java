package com.open.jgm.pki.ca.cert.dto.internal;

import lombok.Data;

import java.util.Date;

/**
 * comment
 *
 * @author luotao
 * @version 1.0.0
 * @date 2024/09/5 0005 19:01
 */
@Data
public class CertDescInfo {
    private String universalName;
    private String organization;
    private String organizationUnit;
    private String country;
    private String province;
    private String city;
    private String street;
    private String email;
    private String cert;
    private String issueOrg;
    private Date certValidStartTime;
    private Date certValidEndTime;
    private String serialNumberHex;
}
