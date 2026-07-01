package com.open.jgm.pki.ca.cert.ca;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * T11：把 {@link AdminTokenInterceptor} 注册到 {@code /api/v2/ca/**}。
 */
@Configuration
@RequiredArgsConstructor
public class CaWebMvcConfig implements WebMvcConfigurer {

    private final AdminTokenInterceptor adminTokenInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(adminTokenInterceptor)
                .addPathPatterns("/api/v2/ca/**");
    }
}
