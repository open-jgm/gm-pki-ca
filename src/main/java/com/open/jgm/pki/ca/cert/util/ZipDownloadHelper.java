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

package com.open.jgm.pki.ca.cert.util;

import cn.hutool.core.util.ZipUtil;
import com.open.jgm.pki.ca.cert.dto.enums.OutputFormat;
import com.open.jgm.pki.ca.cert.dto.response.CaChainResult;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import com.open.jgm.pki.ca.cert.exception.CertException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * HTTP 下载助手：封装证书 ZIP 响应的重复逻辑。
 * <p>
 * T03：按 {@link CertIssuedResult#resolveFormats()} 过滤 PEM / DER / P12 / JKS。
 * CA 链文件（rca/oca/trust/p7b）保持始终输出，方便用户自行信任安装。
 */
@Slf4j
public final class ZipDownloadHelper {

    private ZipDownloadHelper() {}

    /**
     * 将用户证书 + CA 链打包为 ZIP 并写入响应。
     *
     * @param caPrefix 文件名前缀，如 "sm2."、"rsa."、"ecc.prime256v1."
     */
    public static void writeUserCertZip(HttpServletResponse response,
                                        String universalName,
                                        CertIssuedResult cert,
                                        CaChainResult caChain,
                                        String caPrefix) {
        try {
            String encoded = URLEncoder.encode(universalName, StandardCharsets.UTF_8);
            Set<OutputFormat> formats = cert.resolveFormats();

            List<String> names = new ArrayList<>();
            List<InputStream> streams = new ArrayList<>();

            // CA 链（无格式过滤；下载方需要它建立信任）
            addEntry(names, streams, caPrefix + "rca.cer", caChain.getRcaBytes());
            addEntry(names, streams, caPrefix + "oca.cer", caChain.getOcaBytes());
            addEntry(names, streams, caPrefix + "rca.pem", caChain.getRcaPemBytes());
            addEntry(names, streams, caPrefix + "oca.pem", caChain.getOcaPemBytes());
            addEntry(names, streams, caPrefix + "trust.pem", caChain.getTrustPemBytes());
            addEntry(names, streams, caPrefix + "ca.pem",
                    mergeBytes(caChain.getOcaPemBytes(), caChain.getRcaPemBytes()));
            addEntry(names, streams, caPrefix + "trust.p7b", caChain.getP7bBytes());

            // 用户证书 — 按 formats 过滤
            if (formats.contains(OutputFormat.P12)) {
                addEntry(names, streams, encoded + ".p12", cert.getBothP12Byte());
                addEntry(names, streams, encoded + ".sig.p12", cert.getSigP12Byte());
                addEntry(names, streams, encoded + ".enc.p12", cert.getEncP12Byte());
            }
            if (formats.contains(OutputFormat.PEM)) {
                addEntry(names, streams, encoded + ".sig.cert.pem", cert.getSigCertPemByte());
                addEntry(names, streams, encoded + ".sig.key.pem", cert.getSigPriPemByte());
                addEntry(names, streams, encoded + ".enc.cert.pem", cert.getEncCertPemByte());
                addEntry(names, streams, encoded + ".enc.key.pem", cert.getEncPriPemByte());
            }
            if (formats.contains(OutputFormat.DER)) {
                addEntry(names, streams, encoded + ".sig.cert.der", cert.getSigCertByte());
                addEntry(names, streams, encoded + ".enc.cert.der", cert.getEncCertByte());
            }
            if (formats.contains(OutputFormat.JKS)) {
                addEntry(names, streams, encoded + ".jks", cert.getBothJksByte());
                addEntry(names, streams, encoded + ".sig.jks", cert.getSigJksByte());
                addEntry(names, streams, encoded + ".enc.jks", cert.getEncJksByte());
            }

            response.reset();
            response.setHeader("Content-Disposition", "attachment;filename=" + encoded + ".zip");
            response.setContentType("application/octet-stream");
            ZipUtil.zip(response.getOutputStream(),
                    names.toArray(new String[0]),
                    streams.toArray(new InputStream[0]));
        } catch (Exception e) {
            log.error("下载用户证书失败 [{}]", universalName, e);
            throw new CertException("下载证书失败");
        }
    }

    public static void writeCsrZip(HttpServletResponse response,
                                   String commonName,
                                   byte[] csrPem,
                                   byte[] privateKeyPem) {
        try {
            String encoded = URLEncoder.encode(commonName, StandardCharsets.UTF_8);
            List<String> names = new ArrayList<>();
            List<InputStream> streams = new ArrayList<>();

            addEntry(names, streams, encoded + ".csr.pem", csrPem);
            addEntry(names, streams, encoded + ".key.pem", privateKeyPem);

            response.reset();
            response.setHeader("Content-Disposition", "attachment;filename=" + encoded + ".csr.zip");
            response.setContentType("application/octet-stream");
            ZipUtil.zip(response.getOutputStream(),
                    names.toArray(new String[0]),
                    streams.toArray(new InputStream[0]));
        } catch (Exception e) {
            log.error("下载 CSR 失败 [{}]", commonName, e);
            throw new CertException("下载 CSR 失败");
        }
    }

    /**
     * 将 CA 证书链打包为 ZIP 并写入响应。
     */
    public static void writeCaChainZip(HttpServletResponse response,
                                       String zipFileName,
                                       CaChainResult caChain,
                                       String caPrefix) {
        try {
            String[] names = {
                caPrefix + "rca.cer", caPrefix + "oca.cer",
                caPrefix + "rca.pem", caPrefix + "oca.pem",
                caPrefix + "trust.pem", caPrefix + "ca.pem",
                caPrefix + "trust.p7b"
            };
            InputStream[] streams = {
                new ByteArrayInputStream(caChain.getRcaBytes()),
                new ByteArrayInputStream(caChain.getOcaBytes()),
                new ByteArrayInputStream(caChain.getRcaPemBytes()),
                new ByteArrayInputStream(caChain.getOcaPemBytes()),
                new ByteArrayInputStream(caChain.getTrustPemBytes()),
                new ByteArrayInputStream(mergeBytes(caChain.getOcaPemBytes(), caChain.getRcaPemBytes())),
                new ByteArrayInputStream(caChain.getP7bBytes())
            };
            response.reset();
            response.setHeader("Content-Disposition", "attachment;filename=" + zipFileName + ".zip");
            response.setContentType("application/octet-stream");
            ZipUtil.zip(response.getOutputStream(), names, streams);
        } catch (Exception e) {
            log.error("下载CA证书链失败 [{}]", zipFileName, e);
            throw new CertException("下载CA证书失败");
        }
    }

    /**
     * null 安全的字节数组合并。
     */
    public static byte[] mergeBytes(byte[] first, byte[] second) {
        if (first == null && second == null) return new byte[0];
        if (first == null)  return second.clone();
        if (second == null) return first.clone();
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first,  0, result, 0,            first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    /**
     * 仅当 bytes 非空时入栈，避免 ZIP 里出现空文件。
     */
    private static void addEntry(List<String> names, List<InputStream> streams, String name, byte[] bytes) {
        if (bytes == null || bytes.length == 0) return;
        names.add(name);
        streams.add(new ByteArrayInputStream(bytes));
    }
}
