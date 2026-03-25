package com.bootcloud.web.controller;

import com.bootcloud.web.core.admin.AdminRuntimeTenantService;
import com.bootcloud.web.core.tenant.WebRuntimeTenantResolver;
import com.bootcloud.web.core.util.UserTenantSelectionCookieService;
import com.bootcloud.web.core.version.VersionRefreshService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.util.List;

/**
 * 用户端运行时配置接口。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>前端启动时需要知道“当前平台默认租户是谁”，这里统一从 boot-cloud-base 读取。</li>
 *   <li>切换平台默认租户后，前端无需重新发布环境变量即可同步租户头。</li>
 * </ul>
 */
@Slf4j
@RestController
public class BffRuntimeController {

    private final AdminRuntimeTenantService adminRuntimeTenantService;
    private final VersionRefreshService versionRefreshService;
    private final WebRuntimeTenantResolver webRuntimeTenantResolver;
    private final UserTenantSelectionCookieService userTenantSelectionCookieService;

    public BffRuntimeController(
            AdminRuntimeTenantService adminRuntimeTenantService,
            VersionRefreshService versionRefreshService,
            WebRuntimeTenantResolver webRuntimeTenantResolver,
            UserTenantSelectionCookieService userTenantSelectionCookieService
    ) {
        this.adminRuntimeTenantService = adminRuntimeTenantService;
        this.versionRefreshService = versionRefreshService;
        this.webRuntimeTenantResolver = webRuntimeTenantResolver;
        this.userTenantSelectionCookieService = userTenantSelectionCookieService;
    }

    @GetMapping("/api/web/runtime/default-tenant")
    public AdminRuntimeTenantService.DefaultTenantView getDefaultTenant(HttpServletRequest request) {
        AdminRuntimeTenantService.DefaultTenantView platformDefault = adminRuntimeTenantService.getDefaultTenant();
        long resolvedTenantId = webRuntimeTenantResolver.resolveTenantId(request, (Long) null, "runtime_default_tenant");
        if (platformDefault.getTenantId() != null && platformDefault.getTenantId() == resolvedTenantId) {
            return platformDefault;
        }

        AdminRuntimeTenantService.LoginTenantView selected = adminRuntimeTenantService.getEnabledLoginTenantById(resolvedTenantId);
        if (selected == null) {
            if (log.isWarnEnabled()) {
                log.warn("用户端默认租户回退平台默认值：resolvedTenantId={}, reason=selected_tenant_not_enabled", resolvedTenantId);
            }
            return platformDefault;
        }

        AdminRuntimeTenantService.DefaultTenantView out = new AdminRuntimeTenantService.DefaultTenantView();
        out.setTenantId(selected.getId());
        out.setTenantCode(selected.getTenantCode());
        out.setTenantName(selected.getName());
        out.setSiteRole(selected.getSiteRole());
        out.setSource("USER_SELECTED_TENANT");
        return out;
    }

    /**
     * 用户端可选租户站点列表。
     *
     * <ul>
     *   <li>仅在 `boot.cloud.web.user-auth.tenant-site-selector.enabled=true` 时启用。</li>
     *   <li>适合测试环境或多租户演示环境使用。</li>
     * </ul>
     */
    @GetMapping("/api/web/runtime/tenant-sites")
    public RuntimeTenantSitesView listRuntimeTenantSites(
            HttpServletRequest request,
            @RequestParam(value = "preferTenantId", required = false) Long preferTenantId
    ) {
        RuntimeTenantSitesView out = new RuntimeTenantSitesView();
        out.enabled = userTenantSelectionCookieService.isEnabled();

        AdminRuntimeTenantService.DefaultTenantView platformDefault = adminRuntimeTenantService.getDefaultTenant();
        out.defaultTenantId = platformDefault == null ? null : platformDefault.getTenantId();
        out.defaultTenantCode = platformDefault == null ? "" : platformDefault.getTenantCode();

        if (!out.enabled) {
            out.selectedTenantId = null;
            out.effectiveTenantId = out.defaultTenantId;
            out.items = List.of();
            return out;
        }

        List<AdminRuntimeTenantService.LoginTenantView> items = adminRuntimeTenantService.listLoginTenants();
        out.items = items;
        // 跨站场景下 Cookie 可能不可用，允许前端显式传 preferTenantId，
        // 但必须命中可选租户列表才会参与解析，避免非法租户注入。
        Long validatedPreferTenantId = isTenantInList(preferTenantId, items) ? preferTenantId : null;
        if (preferTenantId != null && validatedPreferTenantId == null) {
            log.warn("用户端租户站点列表忽略非法 preferTenantId：preferTenantId={}, reason=not_in_enabled_tenant_list", preferTenantId);
        }
        Long selectedTenantId = userTenantSelectionCookieService.resolveSelectedTenantId(request);
        out.selectedTenantId = isTenantInList(selectedTenantId, items) ? selectedTenantId : out.defaultTenantId;
        out.effectiveTenantId = webRuntimeTenantResolver.resolveTenantId(request, validatedPreferTenantId, "runtime_tenant_sites");
        if (log.isDebugEnabled()) {
            log.debug("用户端租户站点列表加载完成：enabled={}, defaultTenantId={}, selectedTenantId={}, effectiveTenantId={}, preferTenantId={}, size={}",
                    out.enabled, out.defaultTenantId, out.selectedTenantId, out.effectiveTenantId, validatedPreferTenantId, items.size());
        }
        return out;
    }

    /**
     * 用户端选择租户站点。
     */
    @PostMapping("/api/web/runtime/tenant-sites/select")
    public RuntimeTenantSelectView selectRuntimeTenantSite(
            HttpServletResponse response,
            @Valid @RequestBody RuntimeTenantSelectRequest body
    ) {
        RuntimeTenantSelectView out = new RuntimeTenantSelectView();
        out.enabled = userTenantSelectionCookieService.isEnabled();
        if (!out.enabled) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenant site selector is disabled");
        }

        AdminRuntimeTenantService.LoginTenantView selected = adminRuntimeTenantService.getEnabledLoginTenantById(body.tenantId);
        if (selected == null || selected.getId() == null || selected.getId() <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "selected tenant is unavailable");
        }

        userTenantSelectionCookieService.writeSelectedTenantId(response, selected.getId());
        out.selectedTenantId = selected.getId();
        out.tenantCode = selected.getTenantCode();
        out.tenantName = selected.getName();
        out.siteRole = selected.getSiteRole();
        if (log.isInfoEnabled()) {
            log.info("用户端已切换手动租户站点：tenantId={}, tenantCode={}, tenantName={}",
                    out.selectedTenantId, safe(out.tenantCode), safe(out.tenantName));
        }
        return out;
    }

    /**
     * 用户端版本刷新元数据。
     *
     * <ul>
     *   <li>前端会周期性轮询该接口，判断是否需要提示刷新。</li>
     *   <li>currentBuildId 由前端当前构建携带，便于服务端返回 hasUpdate。</li>
     * </ul>
     */
    @GetMapping("/api/web/runtime/version-meta")
    public VersionRefreshService.VersionMetaView getPrimaryVersionMeta(
            @RequestParam(value = "currentBuildId", required = false) String currentBuildId,
            @RequestHeader(value = "X-Client-Build-Id", required = false) String headerBuildId
    ) {
        String resolvedCurrentBuild = (currentBuildId == null || currentBuildId.isBlank()) ? headerBuildId : currentBuildId;
        return versionRefreshService.buildVersionMeta(VersionRefreshService.APP_PRIMARY, resolvedCurrentBuild);
    }

    private static boolean isTenantInList(Long tenantId, List<AdminRuntimeTenantService.LoginTenantView> items) {
        if (tenantId == null || tenantId <= 0 || items == null || items.isEmpty()) {
            return false;
        }
        for (AdminRuntimeTenantService.LoginTenantView item : items) {
            if (item == null || item.getId() == null) {
                continue;
            }
            if (tenantId.equals(item.getId())) {
                return true;
            }
        }
        return false;
    }

    private static String safe(String raw) {
        if (raw == null) {
            return "";
        }
        String value = raw.trim();
        return value.length() <= 64 ? value : value.substring(0, 64);
    }

    public static class RuntimeTenantSitesView {
        /**
         * 租户站点选择器是否启用。
         */
        public boolean enabled;
        /**
         * 平台默认租户 ID。
         */
        public Long defaultTenantId;
        /**
         * 平台默认租户编码。
         */
        public String defaultTenantCode;
        /**
         * 手动选择租户 ID（来自 Cookie）。
         */
        public Long selectedTenantId;
        /**
         * 当前请求生效租户 ID（按解析器优先级计算）。
         */
        public Long effectiveTenantId;
        /**
         * 可选站点列表。
         */
        public List<AdminRuntimeTenantService.LoginTenantView> items = List.of();
    }

    public static class RuntimeTenantSelectRequest {
        /**
         * 目标租户 ID。
         */
        @NotNull
        @Positive
        public Long tenantId;
    }

    public static class RuntimeTenantSelectView {
        /**
         * 租户站点选择器是否启用。
         */
        public boolean enabled;
        /**
         * 已选择租户 ID。
         */
        public Long selectedTenantId;
        /**
         * 已选择租户编码。
         */
        public String tenantCode;
        /**
         * 已选择租户名称。
         */
        public String tenantName;
        /**
         * 站点定位。
         */
        public String siteRole;
    }
}
