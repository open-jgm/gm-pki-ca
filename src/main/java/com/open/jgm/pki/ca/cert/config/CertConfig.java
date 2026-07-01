package com.open.jgm.pki.ca.cert.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
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
public class CertConfig {

    /** P12 密码，生产环境通过环境变量 CERT_P12_PASSWORD 覆盖 */
    @NotBlank
    private String p12Password = "12345678";

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
    @NotBlank
    private String caStorageDir = "./data/ca";

    /**
     * 管理端口令（T11）。所有 {@code /api/v2/ca/**} 请求需在头 {@code X-Admin-Token} 中携带。
     * 空字符串表示拒绝所有调用；生产环境通过 CERT_ADMIN_TOKEN 设定为强口令。
     */
    private String adminToken = "";

    /**
     * 在 Spring 容器启动时统一注册 BC Provider，替代三处重复的 static{} 注册。
     */
    @PostConstruct
    public void registerBcProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
