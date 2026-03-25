package com.bootcloud.base.controller.internal.admin;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.bootcloud.base.core.tenant.admin.TenantDomainAdminService;
import com.bootcloud.base.infra.mybatis.entity.TenantDomainEntity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * 内部管理接口：域名 -> 租户 映射管理（evm_tenant_domain）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该接口直接影响网关的租户解析链路（domain -> tenantId），因此建议只允许内网访问。</li>
 *   <li>domain 写入会标准化（小写、去端口、拒绝协议/路径）。</li>
 * </ul>
 */
@Validated
@RestController
@RequestMapping("/internal/admin/tenant-domains")
public class TenantDomainAdminController {

    private static final Logger log = LoggerFactory.getLogger(TenantDomainAdminController.class);

    private final TenantDomainAdminService domainAdminService;

    public TenantDomainAdminController(TenantDomainAdminService domainAdminService) {
        this.domainAdminService = domainAdminService;
    }

    @GetMapping
    public IPage<TenantDomainView> page(
            @RequestParam(value = "tenantId", required = false) Long tenantId,
            @RequestParam(value = "domainLike", required = false) String domainLike,
            @RequestParam(value = "status", required = false) Integer status,
            @RequestParam(value = "page", defaultValue = "1") @Min(1) int page,
            @RequestParam(value = "size", defaultValue = "20") @Min(1) @Max(200) int size
    ) {
        return domainAdminService.page(tenantId, domainLike, status, page, size).convert(TenantDomainView::from);
    }

    @GetMapping("/{id}")
    public TenantDomainView get(
            @PathVariable("id") long id,
            @RequestParam(value = "tenantId", required = false) Long tenantId
    ) {
        long tid = tenantId == null ? 1L : tenantId;
        TenantDomainEntity e = domainAdminService.get(tid, id);
        if (e == null) {
            throw new IllegalArgumentException("domain mapping not found");
        }
        return TenantDomainView.from(e);
    }

    @PostMapping
    public TenantDomainView create(@Valid @RequestBody CreateRequest body) {
        TenantDomainAdminService.CreateCommand cmd = new TenantDomainAdminService.CreateCommand();
        cmd.tenantId = body.tenantId == null ? 1L : body.tenantId;
        cmd.domain = body.domain;
        cmd.isPrimary = body.isPrimary == null ? 0 : body.isPrimary;
        cmd.status = body.status == null ? 1 : body.status;
        cmd.remark = body.remark;
        TenantDomainEntity e = domainAdminService.create(cmd);
        log.info("内部管理：创建域名映射成功，tenantId={}, domain={}", e.getTenantId(), e.getDomain());
        return TenantDomainView.from(e);
    }

    @PutMapping("/{id}")
    public TenantDomainView update(@PathVariable("id") long id, @Valid @RequestBody UpdateRequest body) {
        TenantDomainAdminService.UpdateCommand cmd = new TenantDomainAdminService.UpdateCommand();
        cmd.tenantId = body.tenantId == null ? 1L : body.tenantId;
        cmd.id = id;
        cmd.domain = body.domain;
        cmd.isPrimary = body.isPrimary;
        cmd.status = body.status;
        cmd.remark = body.remark;
        TenantDomainEntity e = domainAdminService.update(cmd);
        return TenantDomainView.from(e);
    }

    @DeleteMapping("/{id}")
    public DeleteResult delete(@PathVariable("id") long id, @RequestParam(value = "tenantId", required = false) Long tenantId) {
        long tid = tenantId == null ? 1L : tenantId;
        domainAdminService.delete(tid, id);
        log.info("内部管理：删除域名映射成功，tenantId={}, id={}", tid, id);
        return new DeleteResult(true);
    }

    @Validated
    public static class CreateRequest {
        /**
         * 默认 tenantId=1（当前阶段）
         */
        public Long tenantId;

        @NotBlank
        public String domain;

        public Integer isPrimary;
        public Integer status;
        public String remark;
    }

    @Validated
    public static class UpdateRequest {
        /**
         * 默认 tenantId=1（当前阶段）
         */
        public Long tenantId;
        public String domain;
        public Integer isPrimary;
        public Integer status;
        public String remark;
    }

    public record TenantDomainView(
            long id,
            long tenantId,
            String domain,
            Integer isPrimary,
            Integer status,
            String remark
    ) {
        public static TenantDomainView from(TenantDomainEntity e) {
            return new TenantDomainView(
                    e.getId() == null ? 0 : e.getId(),
                    e.getTenantId() == null ? 0 : e.getTenantId(),
                    e.getDomain(),
                    e.getIsPrimary(),
                    e.getStatus(),
                    e.getRemark()
            );
        }
    }

    public record DeleteResult(boolean deleted) {
    }
}
