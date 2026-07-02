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

import com.open.jgm.pki.ca.cert.crypto.CommonUtil;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.request.CsrGenerateRequest;
import com.open.jgm.pki.ca.cert.exception.CertException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.security.KeyPair;

@Service
public class CsrGenerateService {

    public GeneratedCsr generate(CsrGenerateRequest request) {
        if (request == null) {
            throw new CertException("CSR 生成请求不能为空");
        }
        try {
            CertCreateDTO dto = toDto(request);
            X500Name subject = SM2X509CertMaker.buildSubjectDN(dto);
            KeyPair keyPair = SM2X509CertMaker.softSm2KeyPair();
            if (keyPair == null) {
                throw new CertException("SM2 密钥对生成失败");
            }
            PKCS10CertificationRequest csr = CommonUtil.createCSR(
                    subject,
                    keyPair.getPublic(),
                    keyPair.getPrivate(),
                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2);
            byte[] csrPem = SM2X509CertMaker.toPEMFormat(csr.getEncoded(), "CERTIFICATE REQUEST");
            byte[] privateKeyPem = SM2X509CertMaker.toPEMFormat(keyPair.getPrivate(), "PRIVATE KEY");
            return new GeneratedCsr(request.getDnCn(), csrPem, privateKeyPem);
        } catch (CertException e) {
            throw e;
        } catch (Exception e) {
            throw new CertException("CSR 生成失败：" + e.getMessage(), e);
        }
    }

    private static CertCreateDTO toDto(CsrGenerateRequest request) {
        CertCreateDTO dto = new CertCreateDTO();
        dto.setDn_cn(request.getDnCn());
        dto.setDn_c(request.getDnC());
        dto.setDn_st(request.getDnSt());
        dto.setDn_l(request.getDnL());
        dto.setDn_street(request.getDnStreet());
        dto.setDn_o(request.getDnO());
        dto.setDn_ou(request.getDnOu());
        dto.setDn_email(request.getDnEmail());
        return dto;
    }

    public record GeneratedCsr(String commonName, byte[] csrPem, byte[] privateKeyPem) {
        public GeneratedCsr {
            csrPem = csrPem == null ? new byte[0] : csrPem.clone();
            privateKeyPem = privateKeyPem == null ? new byte[0] : privateKeyPem.clone();
        }

        @Override
        public byte[] csrPem() {
            return csrPem.clone();
        }

        @Override
        public byte[] privateKeyPem() {
            return privateKeyPem.clone();
        }
    }
}
