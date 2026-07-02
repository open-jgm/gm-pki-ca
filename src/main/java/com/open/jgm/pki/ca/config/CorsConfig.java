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

package com.open.jgm.pki.ca.config;

import com.open.jgm.pki.ca.cert.config.CertConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class CorsConfig {

    private final CertConfig certConfig;

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        List<String> origins = parseOrigins(certConfig.getCorsAllowedOrigins());
        boolean wildcard = origins.contains("*");
        boolean allowCredentials = certConfig.isCorsAllowCredentials() && !wildcard;

        config.setAllowCredentials(allowCredentials);
        origins.forEach(config::addAllowedOriginPattern);
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.setMaxAge(3600L);

        if (origins.isEmpty()) {
            log.info("CORS origin 白名单为空，仅允许同源访问");
        }
        if (wildcard && certConfig.isCorsAllowCredentials()) {
            log.warn("CORS 配置包含 *，已强制关闭 allowCredentials");
        }

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    private static List<String> parseOrigins(String configured) {
        if (configured == null || configured.isBlank()) {
            return List.of();
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .toList();
    }
}
