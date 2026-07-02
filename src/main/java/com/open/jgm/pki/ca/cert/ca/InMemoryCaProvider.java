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

package com.open.jgm.pki.ca.cert.ca;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.HexUtil;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.open.jgm.pki.ca.cert.config.CertConfig;
import com.open.jgm.pki.ca.cert.crypto.ECCx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.RSAx509CertMaker;
import com.open.jgm.pki.ca.cert.crypto.SM2X509CertMaker;
import com.open.jgm.pki.ca.cert.dto.enums.Algorithm;
import com.open.jgm.pki.ca.cert.exception.CertException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * T07/T09：内存 + 文件持久化的 CA 仓库与 Provider 实现。
 * <p>
 * 启动时：
 * <ol>
 *   <li>注册内置 CA（SM2、RSA、ECC × 3 曲线）。</li>
 *   <li>若 {@link CertConfig#getCaStorageDir()} 下存在 {@code custom-cas.json}，加载到内存。</li>
 * </ol>
 * 运行时：
 * <ul>
 *   <li>{@link #register(CaIdentity)} 写入内存并同步写回 JSON 文件。</li>
 *   <li>{@link #delete(String)} 仅允许自建 CA；同步写回。</li>
 * </ul>
 * 持久化格式见 {@link PersistedCa}：私钥与证书均以 base64 存储；不加密。
 * 生产部署需将存储目录的文件系统权限收紧到运行用户。
 */
@Component
@Slf4j
public class InMemoryCaProvider implements CaProvider {

    private static final String PERSIST_FILE = "custom-cas.json";

    private final CertConfig certConfig;
    private final Map<String, CaIdentity> cas = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Autowired
    public InMemoryCaProvider(CertConfig certConfig) {
        this.certConfig = certConfig;
    }

    @PostConstruct
    public void init() {
        if (certConfig.isDemoCaEnabled()) {
            registerBuiltin();
        } else {
            log.warn("内置 DEMO CA 已禁用，请通过 /api/v2/ca/upload 上传自有 CA");
        }
        loadPersisted();
        log.info("CaProvider initialized: {} CAs total (builtin + custom)", cas.size());
    }

    // ──────────────────────────────────────────────────────────
    // CaProvider 实现
    // ──────────────────────────────────────────────────────────

    @Override
    public CaIdentity getDefault(Algorithm algorithm) {
        if (algorithm == Algorithm.ECC) {
            return getEccDefault(ECCx509CertMaker.CurveType.PRIME256V1.getUrlKey());
        }
        return required(CaIdentity.builtinId(algorithm, null));
    }

    @Override
    public CaIdentity getEccDefault(String curve) {
        return required(CaIdentity.builtinId(Algorithm.ECC, curve));
    }

    @Override
    public Optional<CaIdentity> findById(String caId) {
        if (caId == null || caId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(cas.get(caId));
    }

    @Override
    public List<CaIdentity> list() {
        return new ArrayList<>(cas.values());
    }

    @Override
    public CaIdentity register(CaIdentity ca) {
        if (ca.isBuiltin()) {
            throw new IllegalArgumentException("builtin=true 不能通过 register 注册");
        }
        String caId = (ca.getCaId() == null || ca.getCaId().isBlank())
                ? "custom:" + UUID.randomUUID()
                : ca.getCaId();
        CaIdentity stored = new CaIdentity(
                caId, ca.getName(), ca.getAlgorithm(), ca.getCurve(),
                ca.getSubCaCertDer(), ca.getSubCaPrivateKeyPkcs8(),
                ca.getRootCaCertDer(), false, ca.getCreatedAt());
        cas.put(caId, stored);
        persistAll();
        log.info("CA registered: caId={} algo={} name={}", caId, ca.getAlgorithm(), ca.getName());
        return stored;
    }

    @Override
    public void delete(String caId) {
        CaIdentity ca = cas.get(caId);
        if (ca == null) {
            throw new CertException("CA 不存在: " + caId);
        }
        if (ca.isBuiltin()) {
            throw new IllegalStateException("内置 CA 不允许删除: " + caId);
        }
        cas.remove(caId);
        persistAll();
        log.info("CA deleted: caId={}", caId);
    }

    @Override
    public PrivateKey toPrivateKey(CaIdentity ca) {
        try {
            String algo = jcaAlgo(ca.getAlgorithm());
            KeyFactory kf = KeyFactory.getInstance(algo, BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(ca.getSubCaPrivateKeyPkcs8()));
        } catch (Exception e) {
            throw new CertException("CA 私钥解析失败: " + ca.getCaId(), e);
        }
    }

    @Override
    public X509Certificate toCertificate(CaIdentity ca) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(ca.getSubCaCertDer()));
        } catch (Exception e) {
            throw new CertException("CA 证书解析失败: " + ca.getCaId(), e);
        }
    }

    @Override
    public PublicKey toPublicKey(CaIdentity ca) {
        return toCertificate(ca).getPublicKey();
    }

    private static String jcaAlgo(Algorithm a) {
        return switch (a) {
            case RSA -> "RSA";
            case SM2, ECC -> "EC";
        };
    }

    // ──────────────────────────────────────────────────────────
    // 内置 CA 注册
    // ──────────────────────────────────────────────────────────

    private void registerBuiltin() {
        // Built-in DEMO CA material is public sample data only. Never use it as production trust anchors.
        // SM2
        try {
            byte[] subDer = Base64.decode(SM2X509CertMaker.subCACert);
            byte[] rootDer = Base64.decode(SM2X509CertMaker.rootCACert);
            byte[] priPkcs8 = HexUtil.decodeHex(SM2X509CertMaker.issuerPrivateKeyBase64);
            CaIdentity sm2 = new CaIdentity(
                    CaIdentity.builtinId(Algorithm.SM2, null),
                    "SM2 SUB CA (builtin)",
                    Algorithm.SM2, null,
                    subDer, priPkcs8, rootDer, true, System.currentTimeMillis());
            cas.put(sm2.getCaId(), sm2);
        } catch (Exception e) {
            log.error("注册内置 SM2 CA 失败", e);
        }

        // RSA
        try {
            byte[] subDer = Base64.decode(RSAx509CertMaker.subCACert);
            byte[] rootDer = Base64.decode(RSAx509CertMaker.rootCACert);
            byte[] priPkcs8 = RSAx509CertMaker.subPrivateKey.getEncoded();
            CaIdentity rsa = new CaIdentity(
                    CaIdentity.builtinId(Algorithm.RSA, null),
                    "RSA SUB CA (builtin)",
                    Algorithm.RSA, null,
                    subDer, priPkcs8, rootDer, true, System.currentTimeMillis());
            cas.put(rsa.getCaId(), rsa);
        } catch (Exception e) {
            log.error("注册内置 RSA CA 失败", e);
        }

        // ECC × 3 曲线
        for (ECCx509CertMaker.CurveType ct : ECCx509CertMaker.CurveType.values()) {
            try {
                ECCx509CertMaker.CaBundle bundle = ECCx509CertMaker.CA_BUNDLES.get(ct);
                byte[] subDer = Base64.decode(bundle.subCACert);
                byte[] rootDer = Base64.decode(bundle.rootCACert);
                byte[] priPkcs8 = bundle.subPrivateKey.getEncoded();
                CaIdentity ecc = new CaIdentity(
                        CaIdentity.builtinId(Algorithm.ECC, ct.getUrlKey()),
                        "ECC " + ct.getUrlKey() + " SUB CA (builtin)",
                        Algorithm.ECC, ct.getUrlKey(),
                        subDer, priPkcs8, rootDer, true, System.currentTimeMillis());
                cas.put(ecc.getCaId(), ecc);
            } catch (Exception e) {
                log.error("注册内置 ECC[{}] CA 失败", ct, e);
            }
        }
    }

    // ──────────────────────────────────────────────────────────
    // 持久化（仅自建 CA）
    // ──────────────────────────────────────────────────────────

    private Path persistPath() {
        return Path.of(certConfig.getCaStorageDir(), PERSIST_FILE);
    }

    private void loadPersisted() {
        Path path = persistPath();
        if (!Files.exists(path)) {
            return;
        }
        try {
            String json = Files.readString(path, StandardCharsets.UTF_8);
            PersistedCa[] arr = mapper.readValue(json, PersistedCa[].class);
            int loaded = 0;
            for (PersistedCa p : arr) {
                CaIdentity ca = p.toIdentity();
                if (ca.isBuiltin()) {
                    log.warn("跳过持久化文件中的 builtin 条目: {}", ca.getCaId());
                    continue;
                }
                cas.put(ca.getCaId(), ca);
                loaded++;
            }
            log.info("从 {} 加载自建 CA: {} 条", path, loaded);
        } catch (IOException e) {
            log.error("加载自建 CA 持久化文件失败: {}", path, e);
        }
    }

    private synchronized void persistAll() {
        Path path = persistPath();
        try {
            Files.createDirectories(path.getParent());
            List<PersistedCa> arr = new ArrayList<>();
            for (CaIdentity ca : cas.values()) {
                if (!ca.isBuiltin()) {
                    arr.add(PersistedCa.from(ca));
                }
            }
            String json = mapper.writeValueAsString(arr);
            Files.writeString(path, json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("持久化自建 CA 失败: {}", path, e);
        }
    }

    private CaIdentity required(String caId) {
        CaIdentity ca = cas.get(caId);
        if (ca == null) {
            throw new CertException("内置 CA 未就绪: " + caId);
        }
        return ca;
    }

    // ──────────────────────────────────────────────────────────
    // 持久化用 POJO（公开字段方便 Jackson；不暴露到 API）
    // ──────────────────────────────────────────────────────────

    /**
     * 自建 CA 的持久化形态：私钥与证书均 base64 字符串。
     */
    public static final class PersistedCa {
        public String caId;
        public String name;
        public String algorithm;
        public String curve;
        public String subCaCertB64;
        public String subCaPrivateKeyB64;
        public String rootCaCertB64;
        public long createdAt;

        public static PersistedCa from(CaIdentity ca) {
            PersistedCa p = new PersistedCa();
            p.caId = ca.getCaId();
            p.name = ca.getName();
            p.algorithm = ca.getAlgorithm().name();
            p.curve = ca.getCurve();
            p.subCaCertB64 = java.util.Base64.getEncoder().encodeToString(ca.getSubCaCertDer());
            p.subCaPrivateKeyB64 = java.util.Base64.getEncoder().encodeToString(ca.getSubCaPrivateKeyPkcs8());
            byte[] root = ca.getRootCaCertDer();
            p.rootCaCertB64 = root == null ? null : java.util.Base64.getEncoder().encodeToString(root);
            p.createdAt = ca.getCreatedAt();
            return p;
        }

        public CaIdentity toIdentity() {
            byte[] subDer = java.util.Base64.getDecoder().decode(subCaCertB64);
            byte[] subKey = java.util.Base64.getDecoder().decode(subCaPrivateKeyB64);
            byte[] rootDer = rootCaCertB64 == null ? null : java.util.Base64.getDecoder().decode(rootCaCertB64);
            return new CaIdentity(caId, name, Algorithm.valueOf(algorithm), curve,
                    subDer, subKey, rootDer, false, createdAt);
        }
    }

}
