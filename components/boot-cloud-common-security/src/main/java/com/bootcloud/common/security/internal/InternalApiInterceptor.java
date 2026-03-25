package com.bootcloud.common.security.internal;

import com.bootcloud.common.core.internal.InternalHmacAuth;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;

/**
 * 内部 API 拦截器。
 *
 * <ul>
 *   <li>用途：保护 /internal/** 路径，只允许可信服务调用。</li>
 *   <li>机制：校验内部密钥头是否等于配置的共享密钥，或校验 HMAC 签名。</li>
 *   <li>安全：当 secret 未配置时默认拒绝访问。</li>
 * </ul>
 */
@Slf4j
public class InternalApiInterceptor implements HandlerInterceptor {

    private static final List<String> INTERNAL_API_PATHS = List.of("/internal/**");
    private final PathMatcher pathMatcher = new AntPathMatcher();
    private final InternalAuthProperties properties;

    public InternalApiInterceptor(InternalAuthProperties properties) {
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestPath = request == null ? null : request.getRequestURI();
        if (!StringUtils.hasText(requestPath)) {
            return true;
        }

        if (!isInternalApiPath(requestPath)) {
            return true;
        }

        String expectedSecret = properties == null ? null : properties.getInternalServiceSecret();
        String headerName = properties == null ? null : properties.getInternalServiceHeader();
        if (!StringUtils.hasText(headerName)) {
            headerName = "X-Internal-Service-Token";
        }

        if (!StringUtils.hasText(expectedSecret)) {
            log.warn("内部服务密钥未配置，拒绝访问：path={}", requestPath);
            sendUnauthorizedResponse(response, "内部服务验证未配置");
            return false;
        }

        if (properties != null && properties.isInternalHmacEnabled()) {
            VerifyResult verify = verifyHmac(request, expectedSecret);
            if (verify.ok) {
                if (log.isDebugEnabled()) {
                    log.debug("内部服务 HMAC 验签成功：path={}，serviceName={}", requestPath, verify.serviceName);
                }
                return true;
            }
            if (!properties.isAcceptLegacyServiceToken()) {
                log.warn("内部服务 HMAC 验签失败且未开启旧头兜底：path={}，reason={}", requestPath, verify.reason);
                sendUnauthorizedResponse(response, "内部服务签名无效");
                return false;
            }
            if (log.isDebugEnabled()) {
                log.debug("内部服务 HMAC 验签失败，进入旧头兜底：path={}，reason={}", requestPath, verify.reason);
            }
        }

        String actualSecret = request.getHeader(headerName);
        if (!StringUtils.hasText(actualSecret)) {
            log.warn("缺少内部服务标识头，拒绝访问：path={}，header={}", requestPath, headerName);
            sendUnauthorizedResponse(response, "缺少内部服务标识");
            return false;
        }
        if (!expectedSecret.equals(actualSecret)) {
            log.warn("内部服务标识验证失败，拒绝访问：path={}，header={}，expected={}，actual={}",
                    requestPath, headerName, maskSecret(expectedSecret), maskSecret(actualSecret));
            sendUnauthorizedResponse(response, "内部服务标识无效");
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("内部服务旧头验证成功：path={}，header={}", requestPath, headerName);
        }
        return true;
    }

    private VerifyResult verifyHmac(HttpServletRequest request, String secret) {
        String path = request == null ? "" : request.getRequestURI();
        String method = request == null ? "" : request.getMethod();
        String serviceName = request == null ? null : request.getHeader(InternalHmacAuth.HEADER_SERVICE_NAME);
        String timestamp = request == null ? null : request.getHeader(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP);
        String signature = request == null ? null : request.getHeader(InternalHmacAuth.HEADER_INTERNAL_SIGN);

        if (!StringUtils.hasText(serviceName) || !StringUtils.hasText(timestamp) || !StringUtils.hasText(signature)) {
            return VerifyResult.fail("missing hmac headers", serviceName);
        }
        if (!isAllowedService(serviceName)) {
            return VerifyResult.fail("service not allowed", serviceName);
        }

        long ts;
        try {
            ts = Long.parseLong(timestamp.trim());
        } catch (Exception e) {
            return VerifyResult.fail("invalid timestamp", serviceName);
        }

        long now = Instant.now().getEpochSecond();
        long skew = properties == null ? 300L : properties.getInternalHmacSkewSeconds();
        if (skew <= 0) {
            skew = 300L;
        }
        if (Math.abs(now - ts) > skew) {
            return VerifyResult.fail("timestamp out of window", serviceName);
        }

        String expectedSign = InternalHmacAuth.sign(secret, serviceName.trim(), String.valueOf(ts), method, path);
        byte[] a = expectedSign.getBytes(StandardCharsets.UTF_8);
        byte[] b = signature.trim().getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(a, b)) {
            return VerifyResult.fail("signature mismatch", serviceName);
        }
        return VerifyResult.ok(serviceName);
    }

    private boolean isAllowedService(String serviceName) {
        if (properties == null || properties.getInternalAllowedServices() == null || properties.getInternalAllowedServices().isEmpty()) {
            return true;
        }
        String normalized = serviceName == null ? "" : serviceName.trim();
        if (!StringUtils.hasText(normalized)) {
            return false;
        }
        for (String it : properties.getInternalAllowedServices()) {
            if (!StringUtils.hasText(it)) {
                continue;
            }
            if (normalized.equalsIgnoreCase(it.trim())) {
                return true;
            }
        }
        return false;
    }

    private boolean isInternalApiPath(String path) {
        for (String pattern : INTERNAL_API_PATHS) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    private static String maskSecret(String secret) {
        if (!StringUtils.hasText(secret) || secret.length() <= 8) {
            return "***";
        }
        return secret.substring(0, 4) + "***" + secret.substring(secret.length() - 4);
    }

    private static void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        if (response == null) {
            return;
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        String body = String.format("{\"code\":401,\"message\":\"%s\",\"success\":false,\"data\":null}",
                new String(message.getBytes(StandardCharsets.UTF_8)));
        response.getWriter().write(body);
        response.getWriter().flush();
    }

    private static final class VerifyResult {
        private final boolean ok;
        private final String reason;
        private final String serviceName;

        private VerifyResult(boolean ok, String reason, String serviceName) {
            this.ok = ok;
            this.reason = reason;
            this.serviceName = serviceName;
        }

        private static VerifyResult ok(String serviceName) {
            return new VerifyResult(true, "", serviceName);
        }

        private static VerifyResult fail(String reason, String serviceName) {
            return new VerifyResult(false, reason, serviceName);
        }
    }
}

