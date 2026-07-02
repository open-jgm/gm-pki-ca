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

package com.open.jgm.pki.ca.cert.dto.response;

import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import lombok.Builder;
import lombok.Value;

import java.util.EnumSet;
import java.util.Set;

/**
 * 已签发证书的字节数据聚合（替代 CertSignedDTO + CertP12DTO）。
 * <p>
 * T03：新增 {@link #requestedFormats}（用户请求的输出格式集合）与 JKS 三件套字段，
 * 供 {@code ZipDownloadHelper} 按需过滤打包。
 */
@Value
@Builder
public class CertIssuedResult {

    // ── 签名证书（双证书体系） ──
    byte[] sigP12Byte;
    byte[] sigCertByte;
    byte[] sigCertPemByte;
    byte[] sigPriPemByte;
    byte[] sigKeyPemByte;

    // ── 加密证书（双证书体系；单证书体系填空数组） ──
    byte[] encP12Byte;
    byte[] encCertByte;
    byte[] encCertPemByte;
    byte[] encPriPemByte;
    byte[] encKeyPemByte;

    // ── 合并/信封 ──
    byte[] bothP12Byte;
    byte[] encKeyEnvelopeByte;
    byte[] pwdTxt;

    // ── T03：JKS 三件套（仅 RSA/ECC 在 OutputFormat 包含 JKS 时填充） ──
    byte[] sigJksByte;
    byte[] encJksByte;
    byte[] bothJksByte;

    /** T03：用户请求的输出格式集合；为 null 时 {@code ZipDownloadHelper} 视为「全部」。 */
    Set<OutputFormat> requestedFormats;

    /** 工具：返回非 null 的格式集合，便于下游使用。 */
    public Set<OutputFormat> resolveFormats() {
        return requestedFormats == null || requestedFormats.isEmpty()
                ? EnumSet.allOf(OutputFormat.class)
                : requestedFormats;
    }
}
