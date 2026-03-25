package com.bootcloud.base.core.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.base.config.BaseInternalAuthProperties;
import com.bootcloud.common.core.internal.InternalHmacAuth;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;

/**
 * 内部管理接口鉴权拦截器：校验内部密钥头。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>只保护 {@code /internal/admin/**} 管理接口。</li>
 *   <li>策略：fail-closed（未配置密钥也拒绝），避免误上生产后裸奔。</li>
 *   <li>返回统一 JSON：{@code {"error":"unauthorized","error_description":"..."}}。</li>
 * </ul>
 */
@Component
public class InternalAdminAuthInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(InternalAdminAuthInterceptor.class);

    private final BaseInternalAuthProperties props;
    private final ObjectMapper mapper = new ObjectMapper();

    public InternalAdminAuthInterceptor(BaseInternalAuthProperties props) {
        this.props = props;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String secret = props.getInternalServiceSecret();
        String headerName = props.getInternalServiceHeader();

        if (!StringUtils.hasText(secret) || !StringUtils.hasText(headerName)) {
            // 安全兜底：如果密钥未配置，直接拒绝所有管理接口请求
            log.warn("内部管理接口鉴权失败：未配置 boot.cloud.internal-auth.internal-service-secret 或 internal-service-header，path={}", request.getRequestURI());
            return writeUnauthorized(response, "internal auth not configured");
        }

        if (props.isInternalHmacEnabled()) {
            VerifyResult verify = verifyHmac(request, secret);
            if (verify.ok) {
                if (log.isDebugEnabled()) {
                    log.debug("boot-cloud-base 内部管理接口 HMAC 验签成功：path={}, serviceName={}",
                            request.getRequestURI(), verify.serviceName);
                }
                return true;
            }
            if (!props.isAcceptLegacyServiceToken()) {
                log.warn("boot-cloud-base 内部管理接口 HMAC 验签失败且未开启旧头兜底：path={}, reason={}",
                        request.getRequestURI(), verify.reason);
                return writeUnauthorized(response, "invalid internal signature");
            }
            if (log.isDebugEnabled()) {
                log.debug("boot-cloud-base 内部管理接口 HMAC 验签失败，进入旧头兜底：path={}, reason={}",
                        request.getRequestURI(), verify.reason);
            }
        }

        String provided = request.getHeader(headerName);
        if (!StringUtils.hasText(provided) || !provided.trim().equals(secret)) {
            // 记录必要调试信息（不记录 secret 明文）
            log.warn("内部管理接口鉴权失败：headerMissingOrMismatch，path={}, header={}, remote={}",
                    request.getRequestURI(), headerName, request.getRemoteAddr());
            return writeUnauthorized(response, "invalid internal service token");
        }
        return true;
    }

    private boolean writeUnauthorized(HttpServletResponse response, String desc) throws Exception {
        response.setStatus(401);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        ErrorBody body = new ErrorBody("unauthorized", desc);
        response.getWriter().write(mapper.writeValueAsString(body));
        return false;
    }

    private record ErrorBody(String error, String error_description) {
    }

    private VerifyResult verifyHmac(HttpServletRequest request, String secret) {
        String serviceName = request.getHeader(InternalHmacAuth.HEADER_SERVICE_NAME);
        String timestamp = request.getHeader(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP);
        String signature = request.getHeader(InternalHmacAuth.HEADER_INTERNAL_SIGN);
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
        long skew = props.getInternalHmacSkewSeconds() <= 0 ? 300L : props.getInternalHmacSkewSeconds();
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - ts) > skew) {
            return VerifyResult.fail("timestamp out of window", serviceName);
        }

        String expected = InternalHmacAuth.sign(
                secret,
                serviceName.trim(),
                String.valueOf(ts),
                request.getMethod(),
                request.getRequestURI()
        );
        boolean ok = MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                signature.trim().getBytes(StandardCharsets.UTF_8)
        );
        if (!ok) {
            return VerifyResult.fail("signature mismatch", serviceName);
        }
        return VerifyResult.ok(serviceName);
    }

    private boolean isAllowedService(String serviceName) {
        if (props.getInternalAllowedServices() == null || props.getInternalAllowedServices().isEmpty()) {
            return true;
        }
        String normalized = serviceName == null ? "" : serviceName.trim();
        if (!StringUtils.hasText(normalized)) {
            return false;
        }
        for (String it : props.getInternalAllowedServices()) {
            if (!StringUtils.hasText(it)) {
                continue;
            }
            if (normalized.equalsIgnoreCase(it.trim())) {
                return true;
            }
        }
        return false;
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

