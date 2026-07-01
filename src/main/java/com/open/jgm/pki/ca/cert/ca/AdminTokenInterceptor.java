package com.open.jgm.pki.ca.cert.ca;

import com.open.jgm.pki.ca.cert.config.CertConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;

/**
 * T11：管理端点鉴权拦截器。
 * <p>
 * 对 {@code /api/v2/ca/**} 路径强制要求 HTTP 头 {@code X-Admin-Token} 与
 * {@link CertConfig#getAdminToken()} 一致（常量时间比较防侧信道）；
 * 配置为空时拒绝全部请求（默认安全）。
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AdminTokenInterceptor implements HandlerInterceptor {

    private static final String HEADER = "X-Admin-Token";
    private static final String JSON_401 =
            "{\"code\":\"401\",\"msg\":\"未授权: 缺失或错误的 X-Admin-Token\",\"data\":null,\"success\":false}";

    private final CertConfig certConfig;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String expected = certConfig.getAdminToken();
        String actual = request.getHeader(HEADER);

        if (expected == null || expected.isBlank()) {
            log.warn("admin-token 未配置，拒绝管理端调用: {}", request.getRequestURI());
            return reject(response);
        }
        if (actual == null || !constantTimeEquals(expected, actual)) {
            log.warn("管理端 token 校验失败: uri={} ip={}", request.getRequestURI(), request.getRemoteAddr());
            return reject(response);
        }
        return true;
    }

    private static boolean reject(HttpServletResponse response) throws Exception {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        response.getOutputStream().write(JSON_401.getBytes(StandardCharsets.UTF_8));
        return false;
    }

    /** 常量时间字符串比较，防止 timing-attack。 */
    private static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < x.length; i++) {
            r |= x[i] ^ y[i];
        }
        return r == 0;
    }
}
