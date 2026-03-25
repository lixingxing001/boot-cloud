package com.bootcloud.gateway.core.filter;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 后台租户路由策略。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一收敛“后台路径 × 视角 × 租户来源”的决策逻辑。</li>
 *   <li>网关过滤器只消费决策结果，避免路径规则分散在多处导致回归遗漏。</li>
 * </ul>
 */
@Component
public class AdminTenantRoutingPolicy {

    static final String ADMIN_VIEW_MODE_HEADER = "X-Admin-View-Mode";
    static final String ADMIN_VIEW_TENANT_HEADER = "X-Admin-View-Tenant-Id";
    private static final String ADMIN_VIEW_MODE_SYSTEM = "system";
    private static final String ADMIN_VIEW_MODE_TENANT = "tenant";
    private static final String ADMIN_AUTH_PASSWORD_PATH = "/api/web/admin/auth/password/token";
    private static final String ADMIN_AUTH_REFRESH_PATH = "/api/web/admin/auth/refresh";

    /**
     * 计算后台租户路由决策。
     */
    Decision decide(String path, HttpHeaders headers) {
        boolean adminPath = isAdminPath(path);
        if (!adminPath) {
            return Decision.nonAdmin();
        }

        boolean adminAuthPath = isAdminAuthPath(path);
        boolean systemView = isSystemView(headers);
        Long adminViewTenantId = resolveTenantViewTenantId(headers);
        boolean tenantView = adminViewTenantId != null || isTenantView(headers);
        boolean forceRuntimeTenant = !adminAuthPath && !systemView && adminViewTenantId == null;

        return new Decision(
                adminPath,
                adminAuthPath,
                systemView,
                tenantView,
                adminViewTenantId,
                forceRuntimeTenant
        );
    }

    /**
     * 后台认证 BFF 接口识别。
     */
    static boolean isAdminAuthPath(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        String normalized = path.trim();
        return ADMIN_AUTH_PASSWORD_PATH.equals(normalized)
                || ADMIN_AUTH_REFRESH_PATH.equals(normalized);
    }

    private static boolean isAdminPath(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        String normalized = path.trim();
        return normalized.startsWith("/api/admin/")
                || normalized.startsWith("/api/web/admin/");
    }

    private static boolean isSystemView(HttpHeaders headers) {
        if (headers == null) {
            return false;
        }
        String viewMode = headers.getFirst(ADMIN_VIEW_MODE_HEADER);
        return StringUtils.hasText(viewMode)
                && ADMIN_VIEW_MODE_SYSTEM.equalsIgnoreCase(viewMode.trim());
    }

    private static boolean isTenantView(HttpHeaders headers) {
        if (headers == null) {
            return false;
        }
        String viewMode = headers.getFirst(ADMIN_VIEW_MODE_HEADER);
        return StringUtils.hasText(viewMode)
                && ADMIN_VIEW_MODE_TENANT.equalsIgnoreCase(viewMode.trim());
    }

    private static Long resolveTenantViewTenantId(HttpHeaders headers) {
        if (!isTenantView(headers) || headers == null) {
            return null;
        }
        String rawTenantId = headers.getFirst(ADMIN_VIEW_TENANT_HEADER);
        if (!StringUtils.hasText(rawTenantId)) {
            return null;
        }
        try {
            long tenantId = Long.parseLong(rawTenantId.trim());
            return tenantId > 0 ? tenantId : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    /**
     * 后台租户决策快照。
     */
    record Decision(
            boolean adminPath,
            boolean adminAuthPath,
            boolean adminSystemView,
            boolean adminTenantView,
            Long adminViewTenantId,
            boolean forceRuntimeTenant
    ) {
        static Decision nonAdmin() {
            return new Decision(false, false, false, false, null, false);
        }
    }
}
