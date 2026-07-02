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

package com.open.jgm.pki.ca.cert.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import java.security.Security;

/**
 * 证书模块统一配置，替代三个 Controller 中分散的 static{} BC Provider 注册和硬编码参数。
 * <p>
 * 通过 application.yml 的 cert.* 前缀注入；密钥敏感值生产环境通过环境变量覆盖。
 */
@Configuration
@ConfigurationProperties(prefix = "cert")
@Validated
@Data
@Slf4j
public class CertConfig {

    /** P12 密码，生产环境通过环境变量 CERT_P12_PASSWORD 覆盖；空值允许但会在启动时告警。 */
    private String p12Password = "";

    /** LRU 缓存条目上限 */
    @Min(1)
    private int cacheMaxSize = 100;

    /** LRU 缓存 TTL（分钟） */
    @Min(1)
    private int cacheTtlMinutes = 10;

    /**
     * CSR 路径下服务端生成加密证书的有效月数（国密 SM2 双证书场景）。
     * 生产环境可通过环境变量 CERT_CSR_ENC_CERT_VALID_MONTHS 覆盖。
     */
    @Min(1)
    private int csrEncCertValidMonths = 24;

    /**
     * 自建 CA 持久化目录（T09）。文件名固定 {@code custom-cas.json}。
     * 生产环境通过 CERT_CA_STORAGE_DIR 覆盖，且目录权限应严格收紧到运行用户。
     */
    private String caStorageDir = "./data/ca";

    /**
     * 管理端口令（T11）。所有 {@code /api/v2/ca/**} 请求需在头 {@code X-Admin-Token} 中携带。
     * 空字符串表示拒绝所有调用；生产环境通过 CERT_ADMIN_TOKEN 设定为强口令。
     */
    private String adminToken = "";

    /** 业务接口口令。保护 /api/v2/cert、/api/v2/envelope、/api/v2/crl 相关路径。 */
    private String apiToken = "";

    /** 是否启用内置 DEMO CA；生产 profile 应设置为 false，强制上传自有 CA。 */
    private boolean demoCaEnabled = true;

    /** CORS origin 白名单，逗号分隔；空值表示不开放跨域。 */
    private String corsAllowedOrigins = "";

    /** 是否允许跨域携带凭据；当 origin 包含 * 时强制关闭。 */
    private boolean corsAllowCredentials = false;

    /**
     * 在 Spring 容器启动时统一注册 BC Provider，替代三处重复的 static{} 注册。
     */
    @PostConstruct
    public void registerBcProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (p12Password == null || p12Password.isBlank()) {
            log.warn("CERT_P12_PASSWORD 未配置，P12/JKS 输出将使用空口令；生产环境必须显式配置强口令");
        }
        if (apiToken == null || apiToken.isBlank()) {
            log.warn("CERT_API_TOKEN 未配置，受保护业务接口将默认拒绝调用");
        }
        if (demoCaEnabled) {
            log.warn("内置 DEMO CA 已启用；这些公开样例私钥不得用于生产信任锚或真实证书签发");
        }
    }
}
