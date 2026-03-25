package com.bootcloud.base.controller.internal.admin;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.bootcloud.base.core.tenant.admin.PlatformTenantSettingsService;
import com.bootcloud.base.core.tenant.admin.TenantAdminService;
import com.bootcloud.base.infra.mybatis.entity.TenantEntity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * 内部管理接口：租户管理（evm_tenant）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>路径在 {@code /internal/admin/**}，必须携带内部密钥头。</li>
 *   <li>tenant_code 可兼容历史 siteCode 的概念（后续如需统一，可在业务层做映射）。</li>
 * </ul>
 */
@Validated
@RestController
@RequestMapping("/internal/admin/tenants")
public class TenantAdminController {

    private static final Logger log = LoggerFactory.getLogger(TenantAdminController.class);

    private final TenantAdminService tenantAdminService;
    private final PlatformTenantSettingsService platformTenantSettingsService;

    public TenantAdminController(
            TenantAdminService tenantAdminService,
            PlatformTenantSettingsService platformTenantSettingsService
    ) {
        this.tenantAdminService = tenantAdminService;
        this.platformTenantSettingsService = platformTenantSettingsService;
    }

    @GetMapping
    public IPage<TenantView> page(
            @RequestParam(value = "tenantCodeLike", required = false) String tenantCodeLike,
            @RequestParam(value = "status", required = false) Integer status,
            @RequestParam(value = "page", defaultValue = "1") @Min(1) int page,
            @RequestParam(value = "size", defaultValue = "20") @Min(1) @Max(200) int size
    ) {
        long defaultTenantId = platformTenantSettingsService.getDefaultTenantSnapshot().tenantId();
        return tenantAdminService.page(tenantCodeLike, status, page, size).convert(entity -> TenantView.from(entity, defaultTenantId));
    }

    @GetMapping("/{id}")
    public TenantView get(@PathVariable("id") long id) {
        TenantEntity e = tenantAdminService.get(id);
        if (e == null) {
            throw new IllegalArgumentException("tenant not found");
        }
        long defaultTenantId = platformTenantSettingsService.getDefaultTenantSnapshot().tenantId();
        return TenantView.from(e, defaultTenantId);
    }

    @PostMapping
    public TenantView create(@Valid @RequestBody TenantUpsertRequest body) {
        TenantAdminService.CreateCommand cmd = new TenantAdminService.CreateCommand();
        cmd.tenantCode = body.getTenantCode();
        cmd.name = body.getName();
        cmd.status = body.getStatus() == null ? 1 : body.getStatus();
        cmd.siteRole = body.getSiteRole();
        cmd.remark = body.getRemark();
        TenantEntity e = tenantAdminService.create(cmd);
        log.info("内部管理：创建租户成功，tenantId={}, tenantCode={}", e.getId(), e.getTenantCode());
        long defaultTenantId = platformTenantSettingsService.getDefaultTenantSnapshot().tenantId();
        return TenantView.from(e, defaultTenantId);
    }

    @PutMapping("/{id}")
    public TenantView update(@PathVariable("id") long id, @Valid @RequestBody TenantUpsertRequest body) {
        TenantAdminService.UpdateCommand cmd = new TenantAdminService.UpdateCommand();
        cmd.id = id;
        cmd.name = body.getName();
        cmd.status = body.getStatus();
        cmd.siteRole = body.getSiteRole();
        cmd.remark = body.getRemark();
        TenantEntity e = tenantAdminService.update(cmd);
        long defaultTenantId = platformTenantSettingsService.getDefaultTenantSnapshot().tenantId();
        return TenantView.from(e, defaultTenantId);
    }

    /**
     * 硬删除租户（高危）。
     */
    @DeleteMapping("/{id}")
    public DeleteResult delete(@PathVariable("id") long id) {
        tenantAdminService.delete(id);
        log.info("内部管理：删除租户成功，tenantId={}", id);
        return new DeleteResult(true);
    }

    @GetMapping("/default")
    public DefaultTenantView getDefaultTenant() {
        return DefaultTenantView.from(platformTenantSettingsService.getDefaultTenantSnapshot());
    }

    @PutMapping("/default")
    public DefaultTenantView updateDefaultTenant(@Valid @RequestBody DefaultTenantUpdateRequest body) {
        if (body.getTenantId() == null || body.getTenantId() <= 0) {
            throw new IllegalArgumentException("tenantId must be greater than 0");
        }
        PlatformTenantSettingsService.DefaultTenantSnapshot updated =
                platformTenantSettingsService.updateDefaultTenant(body.getTenantId());
        log.info("内部管理：更新平台默认租户成功，tenantId={}, tenantCode={}", updated.tenantId(), updated.tenantCode());
        return DefaultTenantView.from(updated);
    }

    public record TenantView(
            long id,
            String tenantCode,
            String name,
            Integer status,
            String siteRole,
            String remark,
            boolean defaultTenant
    ) {
        public static TenantView from(TenantEntity e, long defaultTenantId) {
            return new TenantView(
                    e.getId() == null ? 0 : e.getId(),
                    e.getTenantCode(),
                    e.getName(),
                    e.getStatus(),
                    TenantAdminService.normalizeSiteRole(e.getSiteRole()),
                    e.getRemark(),
                    e.getId() != null && e.getId() == defaultTenantId
            );
        }
    }

    public record DefaultTenantView(
            long tenantId,
            String tenantCode,
            String tenantName,
            String siteRole,
            Integer status,
            boolean configured,
            String source,
            long resolvedAt
    ) {
        public static DefaultTenantView from(PlatformTenantSettingsService.DefaultTenantSnapshot snapshot) {
            return new DefaultTenantView(
                    snapshot.tenantId(),
                    snapshot.tenantCode(),
                    snapshot.tenantName(),
                    snapshot.siteRole(),
                    snapshot.status(),
                    snapshot.configured(),
                    snapshot.source(),
                    snapshot.resolvedAt()
            );
        }
    }

    public record DeleteResult(boolean deleted) {
    }

    /**
     * 内部租户写请求。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>这里保持本地 DTO，避免 boot-cloud-base 额外依赖 feign 组件。</li>
     *   <li>字段名与 Feign DTO 保持一致，接口序列化仍可直接对接。</li>
     * </ul>
     */
    public static class TenantUpsertRequest {
        private String tenantCode;
        private String name;
        private Integer status;
        private String siteRole;
        private String remark;

        public String getTenantCode() {
            return tenantCode;
        }

        public void setTenantCode(String tenantCode) {
            this.tenantCode = tenantCode;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Integer getStatus() {
            return status;
        }

        public void setStatus(Integer status) {
            this.status = status;
        }

        public String getSiteRole() {
            return siteRole;
        }

        public void setSiteRole(String siteRole) {
            this.siteRole = siteRole;
        }

        public String getRemark() {
            return remark;
        }

        public void setRemark(String remark) {
            this.remark = remark;
        }
    }

    /**
     * 内部默认租户更新请求。
     */
    public static class DefaultTenantUpdateRequest {
        private Long tenantId;

        public Long getTenantId() {
            return tenantId;
        }

        public void setTenantId(Long tenantId) {
            this.tenantId = tenantId;
        }
    }
}

