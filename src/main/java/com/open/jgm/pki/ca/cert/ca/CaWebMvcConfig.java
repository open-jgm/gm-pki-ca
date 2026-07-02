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

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 注册统一鉴权拦截器，保护 CA 管理、证书签发、数字信封、CRL 和敏感检查相关接口。
 */
@Configuration
@RequiredArgsConstructor
public class CaWebMvcConfig implements WebMvcConfigurer {

    private final AdminTokenInterceptor adminTokenInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(adminTokenInterceptor)
                .addPathPatterns(
                        "/api/v2/ca/**",
                        "/api/v2/cert/**",
                        "/api/v2/envelope/**",
                        "/api/v2/crl/**",
                        "/api/v2/inspect/**");
    }
}
