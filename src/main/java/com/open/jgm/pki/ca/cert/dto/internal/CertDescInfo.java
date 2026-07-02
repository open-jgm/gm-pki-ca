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

package com.open.jgm.pki.ca.cert.dto.internal;

import lombok.Data;

import java.util.Date;

/**
 * comment
 *
 * @author open-gm-jca contributors
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
