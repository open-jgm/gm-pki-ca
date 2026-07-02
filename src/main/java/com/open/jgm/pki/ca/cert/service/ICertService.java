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

package com.open.jgm.pki.ca.cert.service;

import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertDetailResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;

/**
 * 证书服务接口，定义三种算法（SM2 / RSA / ECC）共享的操作契约。
 */
public interface ICertService {

    /**
     * 服务端生成密钥对并签发用户证书，返回证书唯一标识（CN）。
     */
    String issueUserCert(CertIssueRequest request);

    /**
     * 通过 CSR（PKCS#10）签发用户证书，私钥由客户端持有，返回 CN。
     */
    String issueUserCertByCSR(byte[] csrBytes);

    /**
     * 从缓存获取已签发的证书数据。
     */
    CertIssuedResult getIssuedCert(String universalName);

    /**
     * 获取 CA 证书链（根CA + 子CA + P7B + PEM 合并）。
     */
    CaChainResult getCaChain();

    /**
     * 解析任意 X.509 证书，返回可读字段。
     */
    CertDetailResult parseCert(String base64Cert);
}
