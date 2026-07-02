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

package com.open.jgm.pki.ca.cert.crypto;

import com.open.jgm.pki.ca.cert.dto.internal.CertCreateDTO;
import com.open.jgm.pki.ca.cert.dto.internal.CertDescInfo;
import com.open.jgm.pki.ca.cert.util.CertExtensionResolver;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.HexUtil;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * ECC X.509 证书签发工具类，支持三条椭圆曲线：
 * <ul>
 *   <li>prime256v1  (secp256r1 / P-256)   — SHA256withECDSA</li>
 *   <li>brainpoolP256r1                   — SHA256withECDSA</li>
 *   <li>FRP256v1                          — SHA256withECDSA</li>
 * </ul>
 *
 * <b>使用方法：</b>
 * <ol>
 *   <li>将曲线常量留空，在 IDEA 中运行 {@code main()} 获得打印输出</li>
 *   <li>将对应值粘贴回 static final 字段（每条曲线独立一组 6 个值）</li>
 *   <li>重新部署，CA 密钥跨重启稳定</li>
 * </ol>
 */
@Slf4j
public class ECCx509CertMaker {

    // ----------------------------------------------------------------
    // 曲线枚举
    // ----------------------------------------------------------------
    public enum CurveType {
        PRIME256V1("secp256r1",        "SHA256withECDSA", "prime256v1"),
        BRAINPOOL_P256R1("brainpoolP256r1", "SHA256withECDSA", "brainpoolP256r1"),
        FRP256V1("FRP256v1",           "SHA256withECDSA", "FRP256v1");

        /** BouncyCastle ECGenParameterSpec 名称 */
        public final String curveName;
        public final String signAlgo;
        /** 用于 URL path / 缓存 key */
        @Getter
        public final String urlKey;

        CurveType(String curveName, String signAlgo, String urlKey) {
            this.curveName = curveName;
            this.signAlgo  = signAlgo;
            this.urlKey    = urlKey;
        }

        public static CurveType fromUrlKey(String key) {
            for (CurveType c : values()) {
                if (c.urlKey.equalsIgnoreCase(key)) return c;
            }
            throw new IllegalArgumentException("Unknown ECC curve: " + key);
        }
    }

    // ----------------------------------------------------------------
    // CA 密钥包（每条曲线独立一份）
    // ----------------------------------------------------------------
    public static class CaBundle {
        public final PublicKey  rootPublicKey;
        public final PrivateKey rootPrivateKey;
        public final PublicKey  subPublicKey;
        public final PrivateKey subPrivateKey;
        /** Base64 DER 根CA证书 */
        public final String rootCACert;
        /** Base64 DER 子CA证书 */
        public final String subCACert;

        CaBundle(PublicKey rPub, PrivateKey rPri, PublicKey sPub, PrivateKey sPri,
                 String rootCACert, String subCACert) {
            this.rootPublicKey  = rPub;
            this.rootPrivateKey = rPri;
            this.subPublicKey   = sPub;
            this.subPrivateKey  = sPri;
            this.rootCACert     = rootCACert;
            this.subCACert      = subCACert;
        }
    }

    // ----------------------------------------------------------------
    // 内部枚举 & 基础常量
    // ----------------------------------------------------------------
    private enum CertLevel { RootCA, SubCA, EndEntity }

    private static final SecureRandom SERIAL_RANDOM = new SecureRandom();
    static final BouncyCastleProvider BC = new BouncyCastleProvider();
    public static final String PASSWORD = "";

    // ----------------------------------------------------------------
    // prime256v1 (secp256r1 / P-256) 硬编码 CA 密钥对
    // ----------------------------------------------------------------
    static final String PRIME256V1_ROOT_PUB_HEX  = "3059301306072a8648ce3d020106082a8648ce3d03010703420004d681c99088d063b6331a17ca72268b9b2fe5acb5a88c49431b8155ac6b3d84f65b5191ed38cd19ba7cff6294c0b456a777533b60199cd8e0ffb10e60e89e2dbf";
    static final String PRIME256V1_ROOT_PRI_HEX  = "308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420189f4a38f8a8e2024ac64b64b6cad7fc82c992539eb327e2b0e45053c3c014e9a00a06082a8648ce3d030107a14403420004d681c99088d063b6331a17ca72268b9b2fe5acb5a88c49431b8155ac6b3d84f65b5191ed38cd19ba7cff6294c0b456a777533b60199cd8e0ffb10e60e89e2dbf";
    static final String PRIME256V1_ROOT_CA_CERT  = "MIICfTCCAiKgAwIBAgIIHHsnyfuGEAAwCgYIKoZIzj0EAwIwgaExCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjERMA8GA1UEBwwIY2hhbmdzaGExDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTEfMB0GA1UEAwwWRUNDIFBSSU1FMjU2VjEgUk9PVCBDQTAeFw0yNjA1MDYxNjAwMDBaFw00NjA1MDYxNjAwMDBaMIGhMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFaHVuYW4xETAPBgNVBAcMCGNoYW5nc2hhMQ0wCwYDVQQJDARsdWd1MR8wHQYJKoZIhvcNAQkBFhBjcnlwdG9fbHRAcXEuY29tMQ8wDQYDVQQKDAZxaW1pbmcxDTALBgNVBAsMBG1pbWExHzAdBgNVBAMMFkVDQyBQUklNRTI1NlYxIFJPT1QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATWgcmQiNBjtjMaF8pyJoubL+WstaiMSUMbgVWsaz2E9ltRke04zRm6fP9ilMC0Vqd3UztgGZzY4P+xDmDoni2/o0IwQDAdBgNVHQ4EFgQUwg/yuy/FZHtjUpZ2fq1wcudh4M4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAcYwCgYIKoZIzj0EAwIDSQAwRgIhALjYLbTqGAdzCsjlZA9w80pXWCqO7n6sLTwy5tQnhrJgAiEA649soJX96mmj2X/O/etu20anDV57OhaJej/lq/CfC+8=";
    static final String PRIME256V1_ISSUER_PUB_HEX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004cebdbcc90fc97698c8f872fa929aea5a811d8a7bc55dbca566f54cbc616c5d47f2b4a9d9912007cc1bce3704b39a9b9a352ef502e9695156b61e57623b18f162";
    static final String PRIME256V1_ISSUER_PRI_HEX = "308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101042091eef838590af9a2d3061861868ac196c774e41ea395d5805e92f5018fd06373a00a06082a8648ce3d030107a14403420004cebdbcc90fc97698c8f872fa929aea5a811d8a7bc55dbca566f54cbc616c5d47f2b4a9d9912007cc1bce3704b39a9b9a352ef502e9695156b61e57623b18f162";
    static final String PRIME256V1_SUB_CA_CERT   = "MIICnDCCAkKgAwIBAgIIHHsnyf1GEAAwCgYIKoZIzj0EAwIwgaExCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjERMA8GA1UEBwwIY2hhbmdzaGExDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTEfMB0GA1UEAwwWRUNDIFBSSU1FMjU2VjEgUk9PVCBDQTAeFw0yNjA1MDYxNjAwMDBaFw00NjA1MDYxNjAwMDBaMIGgMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFaHVuYW4xETAPBgNVBAcMCGNoYW5nc2hhMQ0wCwYDVQQJDARsdWd1MR8wHQYJKoZIhvcNAQkBFhBjcnlwdG9fbHRAcXEuY29tMQ8wDQYDVQQKDAZxaW1pbmcxDTALBgNVBAsMBG1pbWExHjAcBgNVBAMMFUVDQyBQUklNRTI1NlYxIFNVQiBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM69vMkPyXaYyPhy+pKa6lqBHYp7xV28pWb1TLxhbF1H8rSp2ZEgB8wbzjcEs5qbmjUu9QLpaVFWth5XYjsY8WKjYzBhMB0GA1UdDgQWBBTimEd8EcxJAEmtimpjbt+zXWiykDAfBgNVHSMEGDAWgBTCD/K7L8Vke2NSlnZ+rXBy52HgzjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBxjAKBggqhkjOPQQDAgNIADBFAiEAp6Q3ybNLazacb1GtDQR0jcFEJpydQRu3FbdlPN14ZTECIEOUUkVcfaDXPJHhrSd/r8iZsw+t2nTmYo0HpVcuja+2";

    // ----------------------------------------------------------------
    // brainpoolP256r1 硬编码 CA 密钥对（空字符串 → 启动时动态生成）
    // ----------------------------------------------------------------
    static final String BRAINPOOL_P256R1_ROOT_PUB_HEX  = "305a301406072a8648ce3d020106092b240303020801010703420004530d2c0cca4c0e2fc5f6050f40d9d7737b47558679bd8f13926463e202ae2fd68dc88a87a136f93acbcb95ede28f9ddf4c3986ec2471993fac313793e790440a";
    static final String BRAINPOOL_P256R1_ROOT_PRI_HEX  = "308195020100301406072a8648ce3d020106092b2403030208010107047a307802010104205038b9d7692f546c960ab6ac60584bb449542fac22238a402ebf0ae9dd83d91ea00b06092b2403030208010107a14403420004530d2c0cca4c0e2fc5f6050f40d9d7737b47558679bd8f13926463e202ae2fd68dc88a87a136f93acbcb95ede28f9ddf4c3986ec2471993fac313793e790440a";
    static final String BRAINPOOL_P256R1_ROOT_CA_CERT  = "MIICiTCCAi+gAwIBAgIIHHsnyf/GEAAwCgYIKoZIzj0EAwIwgacxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjERMA8GA1UEBwwIY2hhbmdzaGExDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTElMCMGA1UEAwwcRUNDIEJSQUlOUE9PTF9QMjU2UjEgUk9PVCBDQTAeFw0yNjA1MDYxNjAwMDBaFw00NjA1MDYxNjAwMDBaMIGnMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFaHVuYW4xETAPBgNVBAcMCGNoYW5nc2hhMQ0wCwYDVQQJDARsdWd1MR8wHQYJKoZIhvcNAQkBFhBjcnlwdG9fbHRAcXEuY29tMQ8wDQYDVQQKDAZxaW1pbmcxDTALBgNVBAsMBG1pbWExJTAjBgNVBAMMHEVDQyBCUkFJTlBPT0xfUDI1NlIxIFJPT1QgQ0EwWjAUBgcqhkjOPQIBBgkrJAMDAggBAQcDQgAEUw0sDMpMDi/F9gUPQNnXc3tHVYZ5vY8TkmRj4gKuL9aNyIqHoTb5OsvLle3ij53fTDmG7CRxmT+sMTeT55BECqNCMEAwHQYDVR0OBBYEFEAC/7GR3y6Fc06oxeIxVzjWQrYlMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgHGMAoGCCqGSM49BAMCA0gAMEUCIQCJv9hbfTMaUOTdRq9aW8q8OK04huehY3zwm+XNzM4WvwIgZ6eR1W5+VK6UV/JqkFjR0dEDuzTwq6MUb1WwzSs+X9k=";
    static final String BRAINPOOL_P256R1_ISSUER_PUB_HEX = "305a301406072a8648ce3d020106092b2403030208010107034200042f6643a1bf0a6377d53289d3f18136fb5a5cab2acf3c9b438a449a632857b17f706c6d87082d7cd16632a9ec64b417afdc1b559d908f24c8ee6c6c232f5b608a";
    static final String BRAINPOOL_P256R1_ISSUER_PRI_HEX = "308195020100301406072a8648ce3d020106092b2403030208010107047a30780201010420441f9269a4c27bb48c9fa51715ef0b0ec6583a463fe0a7c31a0d07b7ec2d23eea00b06092b2403030208010107a144034200042f6643a1bf0a6377d53289d3f18136fb5a5cab2acf3c9b438a449a632857b17f706c6d87082d7cd16632a9ec64b417afdc1b559d908f24c8ee6c6c232f5b608a";
    static final String BRAINPOOL_P256R1_SUB_CA_CERT   = "MIICqTCCAk+gAwIBAgIIHHsnygGGEAAwCgYIKoZIzj0EAwIwgacxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjERMA8GA1UEBwwIY2hhbmdzaGExDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTElMCMGA1UEAwwcRUNDIEJSQUlOUE9PTF9QMjU2UjEgUk9PVCBDQTAeFw0yNjA1MDYxNjAwMDBaFw00NjA1MDYxNjAwMDBaMIGmMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFaHVuYW4xETAPBgNVBAcMCGNoYW5nc2hhMQ0wCwYDVQQJDARsdWd1MR8wHQYJKoZIhvcNAQkBFhBjcnlwdG9fbHRAcXEuY29tMQ8wDQYDVQQKDAZxaW1pbmcxDTALBgNVBAsMBG1pbWExJDAiBgNVBAMMG0VDQyBCUkFJTlBPT0xfUDI1NlIxIFNVQiBDQTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNCAAQvZkOhvwpjd9UyidPxgTb7WlyrKs88m0OKRJpjKFexf3BsbYcILXzRZjKp7GS0F6/cG1WdkI8kyO5sbCMvW2CKo2MwYTAdBgNVHQ4EFgQU4BGXbN2kJ0jRaNvYc1RZN5VDvqowHwYDVR0jBBgwFoAUQAL/sZHfLoVzTqjF4jFXONZCtiUwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAcYwCgYIKoZIzj0EAwIDSAAwRQIgWwqppr3jPV9qVd58351IY/nHClOTqwez1nTb0L0OhD0CIQCBlhibDtuDUUgYA2/Np7bIsqQ6nRlCiFTlVXJT1ylU7Q==";

    // ----------------------------------------------------------------
    // FRP256v1 硬编码 CA 密钥对（空字符串 → 启动时动态生成）
    // ----------------------------------------------------------------
    static final String FRP256V1_ROOT_PUB_HEX  = "305b301506072a8648ce3d0201060a2a817a01815f65820001034200044fa7060bd57b9fb79665e5f344c6435ff1d759dbb1268344e87c393fa3fbdfa45fd943b14648374d52bdf5c6bf9178725f996429bc70e28944179f2e99fd1b49";
    static final String FRP256V1_ROOT_PRI_HEX  = "308197020100301506072a8648ce3d0201060a2a817a01815f65820001047b307902010104209b99e82217cd895cb15c6bf0d834927afb0ea58726b4042e74357203121ce56ea00c060a2a817a01815f65820001a144034200044fa7060bd57b9fb79665e5f344c6435ff1d759dbb1268344e87c393fa3fbdfa45fd943b14648374d52bdf5c6bf9178725f996429bc70e28944179f2e99fd1b49";
    static final String FRP256V1_ROOT_CA_CERT  = "MIICejCCAiCgAwIBAgIIHHsnygXGEAAwCgYIKoZIzj0EAwIwgZ8xCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjERMA8GA1UEBwwIY2hhbmdzaGExDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTEdMBsGA1UEAwwURUNDIEZSUDI1NlYxIFJPT1QgQ0EwHhcNMjYwNTA2MTYwMDAwWhcNNDYwNTA2MTYwMDAwWjCBnzELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBWh1bmFuMREwDwYDVQQHDAhjaGFuZ3NoYTENMAsGA1UECQwEbHVndTEfMB0GCSqGSIb3DQEJARYQY3J5cHRvX2x0QHFxLmNvbTEPMA0GA1UECgwGcWltaW5nMQ0wCwYDVQQLDARtaW1hMR0wGwYDVQQDDBRFQ0MgRlJQMjU2VjEgUk9PVCBDQTBbMBUGByqGSM49AgEGCiqBegGBX2WCAAEDQgAET6cGC9V7n7eWZeXzRMZDX/HXWduxJoNE6Hw5P6P736Rf2UOxRkg3TVK99ca/kXhyX5lkKbxw4olEF58umf0bSaNCMEAwHQYDVR0OBBYEFA+jDRyWNEqoAMJBJSefv5aHPJ1ZMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgHGMAoGCCqGSM49BAMCA0gAMEUCICeaOhW3SPISq0d8Vlp88v+Yw7nh+gDRLaLiO0acNC2lAiEAklzuRYg24soApmtR3LZfvcsOttGRH13FO8vFfahcQHA=";
    static final String FRP256V1_ISSUER_PUB_HEX = "305b301506072a8648ce3d0201060a2a817a01815f6582000103420004ec6f8f75da8df4f14c004fdecb48d2f57fc076cc2e4e57ec7c19e92da69794db67d1be6a773f99884d7b95cad7359cd4e391abf3e6bdcfa31df67c3ee961e382";
    static final String FRP256V1_ISSUER_PRI_HEX = "308197020100301506072a8648ce3d0201060a2a817a01815f65820001047b30790201010420bfe2caef1b38b8da1d6f48fb7ac839e7e65cdc31b782d9c667cc511c6f6e564ca00c060a2a817a01815f65820001a14403420004ec6f8f75da8df4f14c004fdecb48d2f57fc076cc2e4e57ec7c19e92da69794db67d1be6a773f99884d7b95cad7359cd4e391abf3e6bdcfa31df67c3ee961e382";
    static final String FRP256V1_SUB_CA_CERT   = "MIICmjCCAkCgAwIBAgIIHHsnygfGEAAwCgYIKoZIzj0EAwIwgZ8xCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVodW5hbjERMA8GA1UEBwwIY2hhbmdzaGExDTALBgNVBAkMBGx1Z3UxHzAdBgkqhkiG9w0BCQEWEGNyeXB0b19sdEBxcS5jb20xDzANBgNVBAoMBnFpbWluZzENMAsGA1UECwwEbWltYTEdMBsGA1UEAwwURUNDIEZSUDI1NlYxIFJPT1QgQ0EwHhcNMjYwNTA2MTYwMDAwWhcNNDYwNTA2MTYwMDAwWjCBnjELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBWh1bmFuMREwDwYDVQQHDAhjaGFuZ3NoYTENMAsGA1UECQwEbHVndTEfMB0GCSqGSIb3DQEJARYQY3J5cHRvX2x0QHFxLmNvbTEPMA0GA1UECgwGcWltaW5nMQ0wCwYDVQQLDARtaW1hMRwwGgYDVQQDDBNFQ0MgRlJQMjU2VjEgU1VCIENBMFswFQYHKoZIzj0CAQYKKoF6AYFfZYIAAQNCAATsb4912o308UwAT97LSNL1f8B2zC5OV+x8GektppeU22fRvmp3P5mITXuVytc1nNTjkavz5r3Pox32fD7pYeOCo2MwYTAdBgNVHQ4EFgQUtaPjSfups4+IpFeZRLbXx8S9lW0wHwYDVR0jBBgwFoAUD6MNHJY0SqgAwkElJ5+/loc8nVkwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAcYwCgYIKoZIzj0EAwIDSAAwRQIhALEAtae2dxb9dGzLE/e9Fy3AGEUTzU35vNbpdltohUmnAiAhY/e73E2+2/YnCr/2Hgtdvt6NsJ30JdGM4sEmi7oxhQ==";

    // ----------------------------------------------------------------
    // 全局 CA Bundle Map（类加载时填充）
    // ----------------------------------------------------------------
    public static final Map<CurveType, CaBundle> CA_BUNDLES = new EnumMap<>(CurveType.class);

    // ----------------------------------------------------------------
    // 静态初始化块
    // ----------------------------------------------------------------
    static {
        Security.addProvider(BC);
        try {
            CA_BUNDLES.put(CurveType.PRIME256V1,
                    buildBundle(CurveType.PRIME256V1,
                            PRIME256V1_ROOT_PUB_HEX, PRIME256V1_ROOT_PRI_HEX,
                            PRIME256V1_ISSUER_PUB_HEX, PRIME256V1_ISSUER_PRI_HEX,
                            PRIME256V1_ROOT_CA_CERT, PRIME256V1_SUB_CA_CERT,
                            "ECC P256 ROOT CA", "ECC P256 SUB CA"));

            CA_BUNDLES.put(CurveType.BRAINPOOL_P256R1,
                    buildBundle(CurveType.BRAINPOOL_P256R1,
                            BRAINPOOL_P256R1_ROOT_PUB_HEX, BRAINPOOL_P256R1_ROOT_PRI_HEX,
                            BRAINPOOL_P256R1_ISSUER_PUB_HEX, BRAINPOOL_P256R1_ISSUER_PRI_HEX,
                            BRAINPOOL_P256R1_ROOT_CA_CERT, BRAINPOOL_P256R1_SUB_CA_CERT,
                            "ECC BP256 ROOT CA", "ECC BP256 SUB CA"));

            CA_BUNDLES.put(CurveType.FRP256V1,
                    buildBundle(CurveType.FRP256V1,
                            FRP256V1_ROOT_PUB_HEX, FRP256V1_ROOT_PRI_HEX,
                            FRP256V1_ISSUER_PUB_HEX, FRP256V1_ISSUER_PRI_HEX,
                            FRP256V1_ROOT_CA_CERT, FRP256V1_SUB_CA_CERT,
                            "ECC FRP256 ROOT CA", "ECC FRP256 SUB CA"));
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // ----------------------------------------------------------------
    // 实例字段（与曲线绑定）
    // ----------------------------------------------------------------
    private final CurveType curveType;
    private final CaBundle  bundle;

    /** T10：可覆盖 CA 子密钥对（自建 CA 签发场景）。默认指向 bundle。 */
    private PublicKey  issuerPubOverride;
    private PrivateKey issuerPriOverride;

    public ECCx509CertMaker(CurveType curveType) {
        this.curveType = curveType;
        this.bundle    = CA_BUNDLES.get(curveType);
        if (this.bundle == null) {
            throw new IllegalStateException("CaBundle not initialized for " + curveType);
        }
    }

    public ECCx509CertMaker withIssuerKeys(PublicKey caPub, PrivateKey caPri) {
        this.issuerPubOverride = caPub;
        this.issuerPriOverride = caPri;
        return this;
    }

    private PublicKey  effectiveIssuerPub() {
        return issuerPubOverride != null ? issuerPubOverride : bundle.subPublicKey;
    }
    private PrivateKey effectiveIssuerPri() {
        return issuerPriOverride != null ? issuerPriOverride : bundle.subPrivateKey;
    }

    // ----------------------------------------------------------------
    // 公共实例方法
    // ----------------------------------------------------------------

    /**
     * 服务端生成 ECC 密钥对，签发用户证书。
     * <p>
     * T02: KeyUsage / ExtendedKeyUsage / BasicConstraints / SAN 均允许通过 dto 覆盖。
     */
    public X509CertificateHolder makeUserCertHolder(KeyPair userKeyPair, CertCreateDTO dto, CertDescInfo descInfo) {
        X500Name issuerDN  = SM2X509CertMaker.buildSubjectDN(descInfo);
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        try {
            Date notBefore = DateUtil.beginOfDay(DateUtil.date());
            Date notAfter  = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
            byte[] csr = CommonUtil.createCSR(subjectDN, userKeyPair.getPublic(), userKeyPair.getPrivate(),
                    curveType.signAlgo).getEncoded();
            // T02: 默认 KeyUsage / EKU，允许 dto 覆盖
            KeyPurposeId[] defaultEku = {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
            KeyUsage defaultUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            KeyUsage usage = CertExtensionResolver.resolveKeyUsage(dto.getKeyUsages(), defaultUsage);
            KeyPurposeId[] eku = CertExtensionResolver.resolveExtendedKeyUsages(dto.getExtendedKeyUsages(), defaultEku);
            List<GeneralName> sans = CertExtensionResolver.resolveSubjectAltNames(dto.getSubjectAltNames());
            BasicConstraints bc = CertExtensionResolver.resolveBasicConstraints(dto.getBasicConstraintsCA(), null, true);
            return buildUserCertHolder(csr, usage, eku, sans, bc, issuerDN, notBefore, notAfter);
        } catch (Exception e) {
            log.error("ECC makeUserCertHolder(KeyPair) failed [{}]", curveType, e);
        }
        return null;
    }

    /**
     * CSR 方式签发用户证书（私钥由客户端持有）。
     */
    public X509CertificateHolder makeUserCertHolder(byte[] csr, CertDescInfo descInfo) {
        return makeUserCertHolder(csr, descInfo, null);
    }

    /**
     * CSR 路径 + 允许 dto 覆盖扩展项（T02）。dto 为 null → 走默认。
     */
    public X509CertificateHolder makeUserCertHolder(byte[] csr, CertDescInfo descInfo, CertCreateDTO dto) {
        X500Name issuerDN = SM2X509CertMaker.buildSubjectDN(descInfo);
        try {
            Date notBefore = DateUtil.beginOfDay(DateUtil.date());
            Date notAfter  = DateUtil.offsetMonth(notBefore, 12);
            KeyPurposeId[] defaultEku = {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
            KeyUsage defaultUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            KeyUsage usage = dto == null ? defaultUsage
                    : CertExtensionResolver.resolveKeyUsage(dto.getKeyUsages(), defaultUsage);
            KeyPurposeId[] eku = dto == null ? defaultEku
                    : CertExtensionResolver.resolveExtendedKeyUsages(dto.getExtendedKeyUsages(), defaultEku);
            List<GeneralName> sans = dto == null ? new LinkedList<>()
                    : CertExtensionResolver.resolveSubjectAltNames(dto.getSubjectAltNames());
            BasicConstraints bc = CertExtensionResolver.resolveBasicConstraints(
                    dto == null ? null : dto.getBasicConstraintsCA(), null, true);
            return buildUserCertHolder(csr, usage, eku, sans, bc, issuerDN, notBefore, notAfter);
        } catch (Exception e) {
            log.error("ECC makeUserCertHolder(csr) failed [{}]", curveType, e);
        }
        return null;
    }

    // ----------------------------------------------------------------
    // 公共静态工具方法
    // ----------------------------------------------------------------

    public static KeyPair generateEccKeyPair(CurveType curveType) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", BC);
            gen.initialize(new ECGenParameterSpec(curveType.curveName), new SecureRandom());
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("generateEccKeyPair failed for " + curveType, e);
        }
    }

    /** 输出 PKCS8 "PRIVATE KEY" PEM */
    public static byte[] toEccPriPem(PrivateKey key) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (PemWriter pw = new PemWriter(new OutputStreamWriter(baos))) {
                pw.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
                pw.flush();
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("toEccPriPem failed", e);
        }
    }

    // ----------------------------------------------------------------
    // 私有：构建 CaBundle（被 static{} 调用）
    // ----------------------------------------------------------------

    private static CaBundle buildBundle(CurveType ct,
            String rootPubHex, String rootPriHex,
            String issuerPubHex, String issuerPriHex,
            String rootCaCertB64, String subCaCertB64,
            String rootCn, String subCn) throws Exception {

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", BC);
        gen.initialize(new ECGenParameterSpec(ct.curveName), new SecureRandom());

        PublicKey  rootPub;
        PrivateKey rootPri;
        if (rootPubHex.isEmpty() || rootPriHex.isEmpty()) {
            KeyPair kp = gen.generateKeyPair();
            rootPub = kp.getPublic();
            rootPri = kp.getPrivate();
        } else {
            KeyFactory kf = KeyFactory.getInstance("EC", BC);
            rootPub = kf.generatePublic (new X509EncodedKeySpec (HexUtil.decodeHex(rootPubHex)));
            rootPri = kf.generatePrivate(new PKCS8EncodedKeySpec(HexUtil.decodeHex(rootPriHex)));
        }

        PublicKey  subPub;
        PrivateKey subPri;
        if (issuerPubHex.isEmpty() || issuerPriHex.isEmpty()) {
            KeyPair kp = gen.generateKeyPair();
            subPub = kp.getPublic();
            subPri = kp.getPrivate();
        } else {
            KeyFactory kf = KeyFactory.getInstance("EC", BC);
            subPub = kf.generatePublic (new X509EncodedKeySpec (HexUtil.decodeHex(issuerPubHex)));
            subPri = kf.generatePrivate(new PKCS8EncodedKeySpec(HexUtil.decodeHex(issuerPriHex)));
        }

        String rootCert;
        String subCert;

        if (rootCaCertB64.isEmpty()) {
            CertCreateDTO rootDto = defaultCaDto(rootCn);
            X509Certificate rc = buildRootCACert(ct, rootDto, rootPub, rootPri);
            rootCert = Base64.encode(rc.getEncoded());
        } else {
            // 验证已有证书可用
            rootCert = rootCaCertB64;
        }

        if (subCaCertB64.isEmpty()) {
            CertCreateDTO subDto = defaultCaDto(subCn);
            X500Name rootDN = SM2X509CertMaker.buildSubjectDN(defaultCaDto(rootCn));
            X509Certificate sc = buildSubCACert(ct, subDto, rootDN, subPub, subPri, rootPub, rootPri);
            subCert = Base64.encode(sc.getEncoded());
        } else {
            subCert = subCaCertB64;
        }

        return new CaBundle(rootPub, rootPri, subPub, subPri, rootCert, subCert);
    }

    // ----------------------------------------------------------------
    // 私有 CA 证书构建
    // ----------------------------------------------------------------

    private static X509Certificate buildRootCACert(CurveType ct, CertCreateDTO dto,
            PublicKey rootPub, PrivateKey rootPri) throws Exception {
        X500Name dn    = SM2X509CertMaker.buildSubjectDN(dto);
        Date notBefore = DateUtil.beginOfDay(DateUtil.date());
        Date notAfter  = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
        byte[] csr     = CommonUtil.createCSR(dn, rootPub, rootPri, ct.signAlgo).getEncoded();
        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                                     | KeyUsage.keyCertSign    | KeyUsage.cRLSign);
        return buildCACert(ct, CertLevel.RootCA, null, csr, usage, null,
                           dn, dn, notBefore, notAfter, rootPub, rootPri);
    }

    private static X509Certificate buildSubCACert(CurveType ct, CertCreateDTO dto, X500Name issuerDN,
            PublicKey subPub, PrivateKey subPri, PublicKey rootPub, PrivateKey rootPri) throws Exception {
        X500Name subjectDN = SM2X509CertMaker.buildSubjectDN(dto);
        Date notBefore     = DateUtil.beginOfDay(DateUtil.date());
        Date notAfter      = DateUtil.offsetMonth(notBefore, dto.getCertValidMonth());
        byte[] csr         = CommonUtil.createCSR(subjectDN, subPub, subPri, ct.signAlgo).getEncoded();
        KeyUsage usage     = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                                         | KeyUsage.keyCertSign    | KeyUsage.cRLSign);
        return buildCACert(ct, CertLevel.SubCA, null, csr, usage, null,
                           subjectDN, issuerDN, notBefore, notAfter, rootPub, rootPri);
    }

    // ----------------------------------------------------------------
    // 核心低级证书构建 — CA 版
    // ----------------------------------------------------------------

    private static X509Certificate buildCACert(CurveType ct, CertLevel certLevel, Integer pathLen,
            byte[] csr, KeyUsage keyUsage, KeyPurposeId[] eku,
            X500Name subjectDN, X500Name issuerDN,
            Date notBefore, Date notAfter,
            PublicKey issPub, PrivateKey issPriv) throws Exception {

        PKCS10CertificationRequest req = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub    = req.getSubjectPublicKeyInfo();

        if (certLevel == CertLevel.RootCA && !issuerDN.equals(subjectDN)) {
            throw new IllegalArgumentException("RootCA: subject must equal issuer");
        }
        if (certLevel == CertLevel.SubCA && issuerDN.equals(subjectDN)) {
            throw new IllegalArgumentException("SubCA: subject must not equal issuer");
        }

        BigInteger serial = randomSerialNumber();
        X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subjectDN, subPub);

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subPub));
        if (certLevel != CertLevel.RootCA) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    ext.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
        }
        BasicConstraints bc = (certLevel == CertLevel.EndEntity) ? new BasicConstraints(false)
                : (pathLen == null ? new BasicConstraints(true) : new BasicConstraints(pathLen));
        builder.addExtension(Extension.basicConstraints, true, bc);
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }

        X509CertificateHolder holder = eccSign(builder, issPriv, ct.signAlgo);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BC.getName()).getCertificate(holder);
        cert.verify(issPub);
        return cert;
    }

    // ----------------------------------------------------------------
    // 核心低级证书构建 — 用户证书版
    // ----------------------------------------------------------------

    private X509CertificateHolder buildUserCertHolder(byte[] csr, KeyUsage keyUsage, KeyPurposeId[] eku,
            List<GeneralName> customSans, BasicConstraints bcOverride,
            X500Name issuerDN, Date notBefore, Date notAfter) throws Exception {

        PKCS10CertificationRequest req = new PKCS10CertificationRequest(csr);
        SubjectPublicKeyInfo subPub    = req.getSubjectPublicKeyInfo();
        X500Name subject               = req.getSubject();

        List<GeneralName> subjectAltNames = new LinkedList<>();
        if (customSans != null && !customSans.isEmpty()) {
            subjectAltNames.addAll(customSans);
        }

        BigInteger serial = randomSerialNumber();
        X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subject, subPub);

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(
                        SubjectPublicKeyInfo.getInstance(effectiveIssuerPub().getEncoded())));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subPub));
        BasicConstraints bc = bcOverride != null ? bcOverride : new BasicConstraints(false);
        builder.addExtension(Extension.basicConstraints, false, bc);
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }
        if (!subjectAltNames.isEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }
        return eccSign(builder, effectiveIssuerPri(), curveType.signAlgo);
    }

    private static X509CertificateHolder eccSign(X509v3CertificateBuilder builder,
            PrivateKey priv, String signAlgo) throws OperatorCreationException {
        ContentSigner signer = new JcaContentSignerBuilder(signAlgo)
                .setProvider(BC.getName()).build(priv);
        return builder.build(signer);
    }


    private static BigInteger randomSerialNumber() {
        byte[] bytes = new byte[16];
        SERIAL_RANDOM.nextBytes(bytes);
        bytes[0] &= 0x7F;
        return new BigInteger(1, bytes);
    }

    // ----------------------------------------------------------------
    // 默认 CA DTO
    // ----------------------------------------------------------------

    private static CertCreateDTO defaultCaDto(String cn) {
        CertCreateDTO dto = new CertCreateDTO();
        dto.setDn_cn(cn);
        dto.setDn_c("CN");
        dto.setDn_st("DEMO");
        dto.setDn_l("DEMO");
        dto.setDn_street("DEMO");
        dto.setDn_email("demo@example.com");
        dto.setDn_o("OPEN-GM-JCA DEMO");
        dto.setDn_ou("DEMO CA");
        dto.setCertValidMonth(240);
        dto.setP12Password(PASSWORD);
        return dto;
    }

    // ----------------------------------------------------------------
    // main() — 离线运行一次，为指定曲线生成并打印 6 个硬编码值
    // ----------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        for (CurveType ct : CurveType.values()) {
            System.out.println("\n===== " + ct.name() + " (" + ct.curveName + ") =====");

            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            gen.initialize(new ECGenParameterSpec(ct.curveName), new SecureRandom());

            // 根CA密钥对
            KeyPair rootKp = gen.generateKeyPair();
            System.out.println(ct.name() + "_ROOT_PUB_HEX  = \""
                    + HexUtil.encodeHexStr(rootKp.getPublic().getEncoded())  + "\";");
            System.out.println(ct.name() + "_ROOT_PRI_HEX  = \""
                    + HexUtil.encodeHexStr(rootKp.getPrivate().getEncoded()) + "\";");

            // 根CA自签证书
            CertCreateDTO rootDto = new CertCreateDTO();
            rootDto.setDn_cn("ECC " + ct.name() + " ROOT CA");
            rootDto.setDn_c("CN"); rootDto.setDn_st("DEMO"); rootDto.setDn_l("DEMO");
            rootDto.setDn_street("DEMO"); rootDto.setDn_email("demo@example.com");
            rootDto.setDn_o("OPEN-GM-JCA DEMO"); rootDto.setDn_ou("DEMO CA"); rootDto.setCertValidMonth(240);
            rootDto.setP12Password(PASSWORD);

            X500Name rootDN = SM2X509CertMaker.buildSubjectDN(rootDto);
            X509Certificate rootCert = buildRootCACert(ct, rootDto, rootKp.getPublic(), rootKp.getPrivate());
            rootCert.verify(rootKp.getPublic());
            System.out.println(ct.name() + "_ROOT_CA_CERT  = \""
                    + Base64.encode(rootCert.getEncoded()) + "\";");

            // 子CA密钥对
            KeyPair subKp = gen.generateKeyPair();
            System.out.println(ct.name() + "_ISSUER_PUB_HEX = \""
                    + HexUtil.encodeHexStr(subKp.getPublic().getEncoded())  + "\";");
            System.out.println(ct.name() + "_ISSUER_PRI_HEX = \""
                    + HexUtil.encodeHexStr(subKp.getPrivate().getEncoded()) + "\";");

            // 子CA证书（根CA私钥签）
            CertCreateDTO subDto = new CertCreateDTO();
            subDto.setDn_cn("ECC " + ct.name() + " SUB CA");
            subDto.setDn_c("CN"); subDto.setDn_st("DEMO"); subDto.setDn_l("DEMO");
            subDto.setDn_street("DEMO"); subDto.setDn_email("demo@example.com");
            subDto.setDn_o("OPEN-GM-JCA DEMO"); subDto.setDn_ou("DEMO CA"); subDto.setCertValidMonth(240);
            subDto.setP12Password(PASSWORD);

            X509Certificate subCert = buildSubCACert(ct, subDto, rootDN,
                    subKp.getPublic(), subKp.getPrivate(), rootKp.getPublic(), rootKp.getPrivate());
            subCert.verify(rootKp.getPublic());
            System.out.println(ct.name() + "_SUB_CA_CERT   = \""
                    + Base64.encode(subCert.getEncoded()) + "\";");
        }
        System.out.println("\n=== 将以上值粘贴回 ECCx509CertMaker 的对应 static final 字段 ===");
    }
}
