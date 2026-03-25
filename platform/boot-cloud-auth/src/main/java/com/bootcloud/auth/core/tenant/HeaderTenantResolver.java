package com.bootcloud.auth.core.tenant;

import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.core.error.OAuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 从请求头 {@code X-Tenant-Id} 解析租户 ID。
 *
 * <p>后续扩展：</p>
 * <ul>
 *   <li>Gateway 侧可通过域名映射 tenant_id，并把结果注入 {@code X-Tenant-Id}。</li>
 *   <li>当需要临时限制某些环境时，仍可通过 allowlist 做额外约束。</li>
 * </ul>
 */
public class HeaderTenantResolver implements TenantResolver {

    private static final Logger log = LoggerFactory.getLogger(HeaderTenantResolver.class);

    private final AuthServerProperties properties;
    private final PlatformDefaultTenantService platformDefaultTenantService;

    public HeaderTenantResolver(AuthServerProperties properties, PlatformDefaultTenantService platformDefaultTenantService) {
        this.properties = properties;
        this.platformDefaultTenantService = platformDefaultTenantService;
    }

    @Override
    public long resolveTenantId(HttpServletRequest request) {
        String s = request.getHeader("X-Tenant-Id");
        if (s == null || s.isBlank()) {
            throw OAuthException.invalidRequest("missing X-Tenant-Id");
        }
        try {
            long v = Long.parseLong(s.trim());
            if (v <= 0) {
                throw OAuthException.invalidRequest("invalid X-Tenant-Id");
            }
            Long runtimeDefaultTenantId = platformDefaultTenantService.getRuntimeDefaultTenantId();
            if (runtimeDefaultTenantId != null && runtimeDefaultTenantId > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("租户头校验通过：tenantId={}, runtimeDefaultTenantId={}", v, runtimeDefaultTenantId);
                }
                if (runtimeDefaultTenantId != v) {
                    log.info("租户头校验通过，命中非默认租户：tenantId={}, runtimeDefaultTenantId={}", v, runtimeDefaultTenantId);
                }
            }
            if (properties.getDeniedTenantIds() != null && !properties.getDeniedTenantIds().isEmpty()) {
                if (properties.getDeniedTenantIds().contains(v)) {
                    log.warn("租户头命中黑名单，拒绝访问：tenantId={}", v);
                    throw OAuthException.invalidRequest("tenant is not allowed");
                }
                if (log.isDebugEnabled()) {
                    log.debug("租户头校验通过，来源=配置黑名单（未命中）: tenantId={}", v);
                }
            }
            if (properties.getAllowedTenantIds() != null && !properties.getAllowedTenantIds().isEmpty()) {
                if (!properties.getAllowedTenantIds().contains(v)) {
                    throw OAuthException.invalidRequest("tenant is not allowed");
                }
                if (log.isDebugEnabled()) {
                    log.debug("租户头校验通过，来源=配置白名单: tenantId={}", v);
                }
            }
            return v;
        } catch (NumberFormatException e) {
            throw OAuthException.invalidRequest("invalid X-Tenant-Id");
        }
    }
}
