package com.bootcloud.web.config.feign;

import com.bootcloud.common.core.internal.InternalHmacAuth;
import com.bootcloud.common.core.security.SecurityUserUtils;
import com.bootcloud.common.core.trace.TraceIdContext;
import feign.RequestInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * boot-cloud-web 调用内部平台服务的 Feign 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用户域服务或平台服务的 /internal/** 由 InternalApiInterceptor 保护，要求携带内部密钥头。</li>
 *   <li>这里统一注入 HMAC 签名头、租户头与 traceId，便于联调与排障。</li>
 * </ul>
 */
@Slf4j
public class WebServiceFeignConfiguration {

    @Bean
    public RequestInterceptor evmWebInternalServicesInterceptor(
            @Value("${boot.cloud.web.services.current-service-name:boot-cloud-web}") String serviceName,
            @Value("${boot.cloud.internal-auth.internal-service-header:X-Internal-Service-Token}") String headerName,
            @Value("${boot.cloud.internal-auth.internal-service-secret:}") String secret,
            @Value("${boot.cloud.web.user-auth.default-tenant-id:0}") long defaultTenantId,
            @Value("${boot.cloud.web.internal-feign.tenant-fallback-enabled:false}") boolean tenantFallbackEnabled,
            @Value("${boot.cloud.auth.client.tenant-header-name:${boot.cloud.auth.client.tenant-header-name:X-Tenant-Id}}") String tenantHeaderName
    ) {
        // 说明：
        // 为彻底收紧租户边界，boot-cloud-web 内部调用不再允许“静默默认租户回退”。
        // 该配置项保留仅用于兼容检测，命中即启动失败，避免环境误配。
        if (tenantFallbackEnabled) {
            log.error("boot-cloud-web 内部调用租户回退已禁用：boot.cloud.web.internal-feign.tenant-fallback-enabled=true, defaultTenantId={}",
                    defaultTenantId);
            throw new IllegalStateException("boot-cloud-web 已禁用内部调用租户回退，请改为显式传递 X-Tenant-Id");
        }
        return template -> {
            if (!StringUtils.hasText(secret)) {
                log.warn("boot-cloud-web 内部服务调用缺少内部密钥配置：prop=boot.cloud.internal-auth.internal-service-secret");
                return;
            }

            // 说明：优先注入 HMAC 认证头，服务端可校验 method + path 防重放与防伪造。
            String resolvedServiceName = StringUtils.hasText(serviceName) ? serviceName.trim() : "boot-cloud-web";
            String path = InternalHmacAuth.normalizePath(template.url());
            String timestamp = InternalHmacAuth.nowTimestampSeconds();
            String signature = InternalHmacAuth.sign(secret, resolvedServiceName, timestamp, template.method(), path);
            template.header(InternalHmacAuth.HEADER_SERVICE_NAME, resolvedServiceName);
            template.header(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP, timestamp);
            template.header(InternalHmacAuth.HEADER_INTERNAL_SIGN, signature);

            // 兼容旧链路：仍注入静态密钥头，便于平滑迁移。
            String hn = StringUtils.hasText(headerName) ? headerName.trim() : "X-Internal-Service-Token";
            template.header(hn, secret);

            String th = StringUtils.hasText(tenantHeaderName) ? tenantHeaderName.trim() : "X-Tenant-Id";
            String tenantId = resolveTenantId(th);
            if (!StringUtils.hasText(tenantId)) {
                tenantId = SecurityUserUtils.getTenantIdStr().orElse(null);
                if (StringUtils.hasText(tenantId) && log.isDebugEnabled()) {
                    log.debug("boot-cloud-web 内部调用租户头回退 SecurityUserContext：tenantId={}", tenantId.trim());
                }
            }
            if (StringUtils.hasText(tenantId)) {
                template.header(th, tenantId.trim());
            } else if (isTenantOptionalInternalPath(path)) {
                if (log.isDebugEnabled()) {
                    log.debug("boot-cloud-web 内部调用租户头缺失但路径允许无租户：path={}", path);
                }
            } else {
                log.error("boot-cloud-web 内部调用缺少租户头且已禁用默认租户回退：path={}, method={}, url={}",
                        path, template.method(), template.url());
                throw new IllegalStateException("缺少租户信息，内部调用已禁用默认租户回退");
            }

            String traceId = TraceIdContext.getOrCreate();
            template.header("X-Trace-Id", traceId);

            // 说明：透传 Accept-Language，让内部服务直接按请求语言返回文案。
            String acceptLanguage = resolveAcceptLanguage();
            if (StringUtils.hasText(acceptLanguage)) {
                template.header("Accept-Language", sanitizeHeaderValue(acceptLanguage, 128));
            }

            if (log.isDebugEnabled()) {
                log.debug("boot-cloud-web 内部调用头注入：serviceName={}, hmacPath={}, legacyHeader={}, tenantHeader={}, tenantId={}, traceId={}, acceptLanguage={}, method={}, url={}",
                        resolvedServiceName, path, hn, th, tenantId, traceId, acceptLanguage, template.method(), template.url());
            }
        };
    }

    private static String resolveTenantId(String tenantHeaderName) {
        try {
            var attrs = RequestContextHolder.getRequestAttributes();
            if (attrs instanceof ServletRequestAttributes sra && sra.getRequest() != null) {
                return sra.getRequest().getHeader(tenantHeaderName);
            }
        } catch (Exception ignore) {
            // 取不到请求上下文时返回空，后续由统一租户策略决定是否允许回退
        }
        return null;
    }

    private static String resolveAcceptLanguage() {
        try {
            var attrs = RequestContextHolder.getRequestAttributes();
            if (attrs instanceof ServletRequestAttributes sra && sra.getRequest() != null) {
                return sra.getRequest().getHeader("Accept-Language");
            }
        } catch (Exception ignore) {
            // 取不到请求上下文时不透传语言头
        }
        return null;
    }

    /**
     * 说明：
     * 这些路径属于后台恢复上下文或系统级管理查询，允许在“登录前”场景不携带租户头。
     * 其余内部接口默认要求显式租户，避免静默漂移到默认租户。
     */
    private static boolean isTenantOptionalInternalPath(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        return path.startsWith("/internal/admin/");
    }

    private static String sanitizeHeaderValue(String raw, int maxChars) {
        if (!StringUtils.hasText(raw)) {
            return "";
        }
        String v = raw.trim().replace("\r", "").replace("\n", "");
        if (maxChars <= 0 || v.length() <= maxChars) {
            return v;
        }
        return v.substring(0, maxChars);
    }
}
