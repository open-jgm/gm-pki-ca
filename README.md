# gm-pki-ca

Java 17 + Spring Boot 3 的国密/PKI CA 示例系统，提供 SM2、RSA、ECC 证书签发、CSR 解析/生成/两步签发、自建 CA 管理、CRL、证书/密钥/链解析、ASN.1 与编解码工具、SM2/SM4 数字信封等能力。

## 安全警示

内置 CA 仅供 DEMO / 本地测试使用。仓库内置 RootCA/SubCA 密钥材料是公开样例，任何人都可以取得这些私钥。生产环境必须通过 /api/v2/ca/upload 上传自有 CA，并通过环境变量配置强口令和访问 token。

生产前至少设置环境变量：CERT_P12_PASSWORD、CERT_ADMIN_TOKEN、CERT_API_TOKEN、CORS_ALLOWED_ORIGINS。

## 功能

- 统一证书签发：/api/v2/cert/issue
- SM2/RSA/ECC 证书签发与下载
- CSR 生成、解析、预览、签发
- 自建 CA 上传、列表、详情、删除
- CRL 生成与解析
- 证书、私钥、证书链检查
- SM2/SM4 数字信封加密、解密、解析
- ASN.1、Base64、Hex 工具

## 快速开始

    mvn clean test
    mvn spring-boot:run

默认端口：8888。访问静态页面：http://localhost:8888/

## 常用命令

    mvn clean compile
    mvn test
    mvn -Dtest=Sm4UtilTest test
    mvn -Dtest=Sm4UtilTest#encryptDecrypt_roundTrip test
    mvn clean package
    java -jar target/gm-pki-ca-1.0.0.jar
    mvn dependency:tree

## 配置项

| 环境变量 | 说明 | 默认 |
| --- | --- | --- |
| CERT_P12_PASSWORD | 生成 P12/JKS 输出时使用的口令。未设置时使用空口令并打印 WARN。 | 空 |
| CERT_ADMIN_TOKEN | /api/v2/ca/** 管理接口 token。空值拒绝管理调用。 | 空 |
| CERT_API_TOKEN | /api/v2/cert/**、/api/v2/envelope/**、/api/v2/crl/** 等业务接口 token。空值拒绝受保护调用。 | 空 |
| CORS_ALLOWED_ORIGINS | CORS origin 白名单，逗号分隔。 | 空 |
| CORS_ALLOW_CREDENTIALS | 是否允许跨域携带凭据。 | false |
| CERT_CA_STORAGE_DIR | 自建 CA 元数据目录。生产环境需限制目录权限。 | ./data/ca |
| LOG_PATH | 日志目录。 | ./logs |

API 文档见 docs/api.md。安全部署见 docs/security.md。

## License

Apache License 2.0. See LICENSE and NOTICE.
