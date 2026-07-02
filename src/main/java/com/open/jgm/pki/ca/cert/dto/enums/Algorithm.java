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

import com.open.jgm.pki.ca.cert.dto.request.CertIssueRequest;

/**
 * 证书算法枚举：覆盖国密 SM2、国际 RSA、ECC（椭圆曲线）。
 * <p>
 * T01 起作为 {@link CertIssueRequest#getAlgorithm()} 的合法取值，
 * 用于在统一入口下区分签发算法。各算法 Service 可以校验请求与自身一致。
 */
public enum Algorithm {

    SM2,
    RSA,
    ECC;

    /**
     * 大小写不敏感的安全解析；返回 {@code null} 表示未指定。
     */
    public static Algorithm parseOrNull(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Algorithm.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported algorithm: " + raw);
        }
    }
}
