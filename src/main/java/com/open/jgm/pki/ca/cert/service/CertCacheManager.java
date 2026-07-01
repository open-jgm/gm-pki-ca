package com.open.jgm.pki.ca.cert.service;

import cn.hutool.cache.Cache;
import cn.hutool.cache.CacheUtil;
import com.open.jgm.pki.ca.cert.config.CertConfig;
import com.open.jgm.pki.ca.cert.dto.response.CertIssuedResult;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 统一缓存管理，替代三个 Controller 中各自独立的静态 LRU Cache。
 */
@Component
@RequiredArgsConstructor
public class CertCacheManager {

    private final CertConfig certConfig;

    private Cache<String, CertIssuedResult> sm2Cache;
    private Cache<String, CertIssuedResult> rsaCache;
    private Cache<String, CertIssuedResult> eccCache;

    @PostConstruct
    public void init() {
        long ttlMs = (long) certConfig.getCacheTtlMinutes() * 60 * 1000L;
        int  maxSize = certConfig.getCacheMaxSize();
        sm2Cache = CacheUtil.newLRUCache(maxSize, ttlMs);
        rsaCache = CacheUtil.newLRUCache(maxSize, ttlMs);
        eccCache = CacheUtil.newLRUCache(maxSize, ttlMs);
    }

    // ── SM2 ──────────────────────────────────────────────
    public void putSm2(String cn, CertIssuedResult result) {
        sm2Cache.put("SM2:" + cn, result);
    }

    public CertIssuedResult getSm2(String cn) {
        return sm2Cache.get("SM2:" + cn);
    }

    public boolean containsSm2(String cn) {
        return sm2Cache.containsKey("SM2:" + cn);
    }

    // ── RSA ──────────────────────────────────────────────
    public void putRsa(String cn, CertIssuedResult result) {
        rsaCache.put("RSA:" + cn, result);
    }

    public CertIssuedResult getRsa(String cn) {
        return rsaCache.get("RSA:" + cn);
    }

    public boolean containsRsa(String cn) {
        return rsaCache.containsKey("RSA:" + cn);
    }

    // ── ECC ──────────────────────────────────────────────
    public void putEcc(String curve, String cn, CertIssuedResult result) {
        eccCache.put("ECC:" + curve + ":" + cn, result);
    }

    public CertIssuedResult getEcc(String curve, String cn) {
        return eccCache.get("ECC:" + curve + ":" + cn);
    }

    public boolean containsEcc(String curve, String cn) {
        return eccCache.containsKey("ECC:" + curve + ":" + cn);
    }
}
