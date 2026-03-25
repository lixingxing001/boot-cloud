package com.bootcloud.web.core.tenant;

import com.bootcloud.web.core.admin.AdminRuntimeTenantService;
import com.bootcloud.web.core.util.UserTenantSelectionCookieService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 用户端 BFF 运行时租户解析器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一收口用户端登录相关接口的租户来源，避免不同控制器各自决定是否回退到 1。</li>
 *   <li>优先级：显式参数 -> 手动选择 Cookie -> 请求头 X-Tenant-Id -> 运行时默认租户。</li>
 *   <li>一旦租户值非法，直接抛错并保留调试日志，方便联调定位。</li>
 * </ul>
 */
@Slf4j
@Component
public class WebRuntimeTenantResolver {

    private final AdminRuntimeTenantService adminRuntimeTenantService;
    private final UserTenantSelectionCookieService userTenantSelectionCookieService;

    public WebRuntimeTenantResolver(
            AdminRuntimeTenantService adminRuntimeTenantService,
            UserTenantSelectionCookieService userTenantSelectionCookieService
    ) {
        this.adminRuntimeTenantService = adminRuntimeTenantService;
        this.userTenantSelectionCookieService = userTenantSelectionCookieService;
    }

    /**
     * 从请求头或运行时默认租户解析租户。
     */
    public String resolveTenantId(HttpServletRequest request, String scene) {
        return String.valueOf(resolveTenantIdInternal(request, null, scene));
    }

    /**
     * 从显式参数、请求头或运行时默认租户解析租户。
     */
    public long resolveTenantId(HttpServletRequest request, Long explicitTenantId, String scene) {
        return resolveTenantIdInternal(request, explicitTenantId, scene);
    }

    private long resolveTenantIdInternal(HttpServletRequest request, Long explicitTenantId, String scene) {
        Long normalizedExplicitTenantId = normalizePositive(explicitTenantId == null ? null : String.valueOf(explicitTenantId));
        if (normalizedExplicitTenantId != null) {
            if (log.isDebugEnabled()) {
                log.debug("用户端运行时租户解析命中显式参数：scene={}, tenantId={}", safe(scene), normalizedExplicitTenantId);
            }
            return normalizedExplicitTenantId;
        }

        Long selectedTenantId = userTenantSelectionCookieService.resolveSelectedTenantId(request);
        if (selectedTenantId != null) {
            try {
                AdminRuntimeTenantService.LoginTenantView selectedTenant = adminRuntimeTenantService.getEnabledLoginTenantById(selectedTenantId);
                if (selectedTenant != null && selectedTenant.getId() != null && selectedTenant.getId() > 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("用户端运行时租户解析命中手动选择 Cookie：scene={}, tenantId={}", safe(scene), selectedTenant.getId());
                    }
                    return selectedTenant.getId();
                }
                log.warn("用户端运行时租户解析忽略无效手动租户：scene={}, tenantId={}, reason=tenant_not_enabled_or_missing",
                        safe(scene), selectedTenantId);
            } catch (Exception ex) {
                log.warn("用户端运行时租户解析校验手动租户失败：scene={}, tenantId={}, msg={}",
                        safe(scene), selectedTenantId, ex.getMessage());
            }
        }

        String headerTenantId = request == null ? null : request.getHeader("X-Tenant-Id");
        Long normalizedHeaderTenantId = normalizePositive(headerTenantId);
        if (normalizedHeaderTenantId != null) {
            if (log.isDebugEnabled()) {
                log.debug("用户端运行时租户解析命中请求头：scene={}, tenantId={}", safe(scene), normalizedHeaderTenantId);
            }
            return normalizedHeaderTenantId;
        }

        AdminRuntimeTenantService.DefaultTenantView runtimeDefault = adminRuntimeTenantService.getDefaultTenant();
        Long runtimeTenantId = runtimeDefault == null ? null : runtimeDefault.getTenantId();
        if (runtimeTenantId == null || runtimeTenantId <= 0) {
            log.error("用户端运行时租户解析失败：scene={}, reason=runtime_default_missing", safe(scene));
            throw new IllegalStateException("加载用户端运行时默认租户失败");
        }

        log.info("用户端运行时租户解析回退默认租户：scene={}, tenantId={}, tenantCode={}, source={}",
                safe(scene),
                runtimeTenantId,
                runtimeDefault.getTenantCode(),
                runtimeDefault.getSource());
        return runtimeTenantId;
    }

    private static Long normalizePositive(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        try {
            long value = Long.parseLong(raw.trim());
            return value > 0 ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String safe(String raw) {
        return StringUtils.hasText(raw) ? raw.trim() : "";
    }
}
