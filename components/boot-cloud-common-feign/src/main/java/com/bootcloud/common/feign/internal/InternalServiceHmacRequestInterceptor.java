package com.bootcloud.common.feign.internal;

import com.bootcloud.common.core.internal.InternalHmacAuth;
import com.bootcloud.common.core.security.SecurityUserUtils;
import com.bootcloud.common.core.trace.TraceIdContext;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * 内部服务调用签名拦截器（method + path 维度）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>头：X-Service-Name / X-Internal-Timestamp(秒) / X-Internal-Sign(hex(HMAC-SHA256))</li>
 *   <li>签名串：serviceName:timestamp:method:path</li>
 *   <li>Trace：兜底透传 X-Trace-Id，便于跨服务排障</li>
 * </ul>
 */
@Slf4j
public class InternalServiceHmacRequestInterceptor implements RequestInterceptor {

    private static final String TRACE_HEADER = "X-Trace-Id";
    private static final String TENANT_HEADER = "X-Tenant-Id";

    private final String serviceName;
    private final String secret;
    private final boolean debugLog;

    public InternalServiceHmacRequestInterceptor(String serviceName, String secret, boolean debugLog) {
        this.serviceName = serviceName;
        this.secret = secret;
        this.debugLog = debugLog;
    }

    @Override
    public void apply(RequestTemplate template) {
        if (template == null) {
            return;
        }
        if (!StringUtils.hasText(serviceName) || !StringUtils.hasText(secret)) {
            // 说明：缺配置时不抛异常，避免启动失败，交给上游接口报错并在日志里暴露问题
            if (debugLog) {
                log.warn("内部 Feign 签名拦截器缺少配置：serviceNamePresent={}, secretPresent={}",
                        StringUtils.hasText(serviceName), StringUtils.hasText(secret));
            }
            return;
        }

        String method = template.method() == null ? "" : template.method().toUpperCase();
        String path = InternalHmacAuth.normalizePath(template.url());
        String timestamp = InternalHmacAuth.nowTimestampSeconds();
        String signature = InternalHmacAuth.sign(secret, serviceName, timestamp, method, path);

        template.header(InternalHmacAuth.HEADER_SERVICE_NAME, serviceName);
        template.header(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP, timestamp);
        template.header(InternalHmacAuth.HEADER_INTERNAL_SIGN, signature);

        String traceId = TraceIdContext.get();
        if (!StringUtils.hasText(traceId)) {
            traceId = TraceIdContext.getOrCreate();
        }
        if (StringUtils.hasText(traceId)) {
            template.header(TRACE_HEADER, traceId.trim());
        }
        // 说明：
        // 1. 优先透传当前 HTTP 请求头中的 X-Tenant-Id，保证后台 super_admin 右上角工作站点切换后，
        //    下游内部服务收到的是“当前操作租户”，不会被 token 自带 tenant 覆盖。
        // 2. 若当前线程没有请求上下文，再回退到 SecurityUser tenant，兼容定时任务与异步线程。
        String requestTenantId = resolveRequestTenantId();
        String securityTenantId = SecurityUserUtils.getTenantIdStr()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .orElse(null);
        String effectiveTenantId = StringUtils.hasText(requestTenantId) ? requestTenantId : securityTenantId;
        if (StringUtils.hasText(effectiveTenantId)) {
            template.header(TENANT_HEADER, effectiveTenantId);
        }

        if (debugLog) {
            log.debug("内部 Feign 签名注入：method={}, path={}, serviceName={}, timestamp={}, traceId={}, requestTenantId={}, securityTenantId={}, effectiveTenantId={}",
                    method, path, serviceName, timestamp, traceId, requestTenantId, securityTenantId, effectiveTenantId);
        }
    }

    private static String resolveRequestTenantId() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return null;
        }
        try {
            Object request = attrs.getClass().getMethod("getRequest").invoke(attrs);
            if (request == null) {
                return null;
            }
            Object raw = request.getClass().getMethod("getHeader", String.class).invoke(request, TENANT_HEADER);
            if (!(raw instanceof String value) || !StringUtils.hasText(value)) {
                return null;
            }
            return value.trim();
        } catch (Exception ex) {
            // 说明：boot-cloud-common-feign 组件不强依赖 servlet API，这里取不到请求上下文时直接回退安全上下文租户。
            return null;
        }
    }
}
