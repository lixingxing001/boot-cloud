package com.bootcloud.web.controller;

import com.bootcloud.web.core.admin.AdminRuntimeTenantService;
import com.bootcloud.web.core.version.VersionRefreshService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 后台运行时配置接口。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该接口给后台登录页和会话恢复流程使用。</li>
 *   <li>返回当前后台应使用的默认租户，前端据此注入 X-Tenant-Id。</li>
 * </ul>
 */
@RestController
public class BffAdminRuntimeController {

    private final AdminRuntimeTenantService adminRuntimeTenantService;
    private final VersionRefreshService versionRefreshService;

    public BffAdminRuntimeController(
            AdminRuntimeTenantService adminRuntimeTenantService,
            VersionRefreshService versionRefreshService
    ) {
        this.adminRuntimeTenantService = adminRuntimeTenantService;
        this.versionRefreshService = versionRefreshService;
    }

    @GetMapping("/api/web/admin/runtime/default-tenant")
    public AdminRuntimeTenantService.DefaultTenantView getDefaultTenant() {
        return adminRuntimeTenantService.getDefaultTenant();
    }

    /**
     * 登录页租户候选列表。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该接口给后台登录页下拉框使用。</li>
     *   <li>只返回最小展示字段，前端用于“选择登录租户”。</li>
     * </ul>
     */
    @GetMapping("/api/web/admin/runtime/login-tenants")
    public List<AdminRuntimeTenantService.LoginTenantView> listLoginTenants() {
        return adminRuntimeTenantService.listLoginTenants();
    }

    /**
     * 后台版本刷新元数据。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>后台前端轮询该接口，用于提示“管理端需要刷新”。</li>
     *   <li>返回结构与用户端保持一致，便于前端复用检测逻辑。</li>
     * </ul>
     */
    @GetMapping("/api/web/admin/runtime/version-meta")
    public VersionRefreshService.VersionMetaView getAdminVersionMeta(
            @RequestParam(value = "currentBuildId", required = false) String currentBuildId,
            @RequestHeader(value = "X-Client-Build-Id", required = false) String headerBuildId
    ) {
        String resolvedCurrentBuild = (currentBuildId == null || currentBuildId.isBlank()) ? headerBuildId : currentBuildId;
        return versionRefreshService.buildVersionMeta(VersionRefreshService.APP_ADMIN, resolvedCurrentBuild);
    }
}
