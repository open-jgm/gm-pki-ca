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

package com.open.jgm.pki.ca.cert.dto.enums;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 用户证书输出格式枚举：PEM / DER / P12 / JKS。
 * <p>
 * T01 阶段：DTO 层接收并透传该集合到 {@code CertIssuedResult.requestedFormats}，
 * 为 T03 的 ZIP 按需打包提供数据基础。当请求未指定时，默认为「全部格式」。
 * <p>
 * 注意：JKS 仅在 RSA / ECC 上可用；SM2 走 PKCS12（详见缺失分析文档第五章风险）。
 */
public enum OutputFormat {

    PEM,
    DER,
    P12,
    JKS;

    /**
     * 大小写不敏感解析；空集合返回「全部格式」。
     */
    public static Set<OutputFormat> parseOrAll(List<String> raws) {
        if (raws == null || raws.isEmpty()) {
            return EnumSet.allOf(OutputFormat.class);
        }
        Set<OutputFormat> result = new LinkedHashSet<>();
        for (String raw : raws) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            try {
                result.add(OutputFormat.valueOf(raw.trim().toUpperCase()));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Unsupported outputFormat: " + raw
                        + " (allowed: " + Arrays.toString(values()) + ")");
            }
        }
        return result.isEmpty() ? EnumSet.allOf(OutputFormat.class) : result;
    }
}
