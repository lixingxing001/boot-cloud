package com.bootcloud.base.core.tenant.admin;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.bootcloud.base.infra.mybatis.entity.TenantEntity;
import com.bootcloud.base.infra.mybatis.mapper.TenantMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * 租户管理服务（boot-cloud-base）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该服务只用于内部管理 API（/internal/admin/**）。</li>
 *   <li>当前阶段 auth 侧仍强制 tenantId=1；但这里先把租户管理做齐，方便后续灰度放开。</li>
 * </ul>
 */
@Service
public class TenantAdminService {

    public static final String SITE_ROLE_PRIMARY_PORTAL = PlatformTenantSettingsService.SITE_ROLE_PRIMARY_PORTAL;
    public static final String SITE_ROLE_BUSINESS_SITE = PlatformTenantSettingsService.SITE_ROLE_BUSINESS_SITE;

    private static final Logger log = LoggerFactory.getLogger(TenantAdminService.class);

    private final TenantMapper tenantMapper;

    public TenantAdminService(TenantMapper tenantMapper) {
        this.tenantMapper = tenantMapper;
    }

    public IPage<TenantEntity> page(String tenantCodeLike, Integer status, int pageNo, int pageSize) {
        LambdaQueryWrapper<TenantEntity> qw = new LambdaQueryWrapper<TenantEntity>()
                .orderByDesc(TenantEntity::getId);
        if (StringUtils.hasText(tenantCodeLike)) {
            qw.like(TenantEntity::getTenantCode, tenantCodeLike.trim());
        }
        if (status != null) {
            qw.eq(TenantEntity::getStatus, status);
        }
        return tenantMapper.selectPage(new Page<>(pageNo, pageSize), qw);
    }

    public TenantEntity get(long id) {
        return tenantMapper.selectById(id);
    }

    @Transactional
    public TenantEntity create(CreateCommand cmd) {
        if (!StringUtils.hasText(cmd.tenantCode)) {
            throw new IllegalArgumentException("tenant_code is required");
        }
        if (!StringUtils.hasText(cmd.name)) {
            throw new IllegalArgumentException("name is required");
        }

        String tenantCode = cmd.tenantCode.trim();
        TenantEntity existed = tenantMapper.selectOne(new LambdaQueryWrapper<TenantEntity>()
                .eq(TenantEntity::getTenantCode, tenantCode)
                .last("LIMIT 1"));
        if (existed != null) {
            throw new IllegalArgumentException("tenant_code already exists");
        }

        TenantEntity e = new TenantEntity();
        e.setTenantCode(tenantCode);
        e.setName(cmd.name.trim());
        e.setStatus(cmd.status == null ? 1 : cmd.status);
        e.setSiteRole(normalizeSiteRole(cmd.siteRole));
        e.setRemark(StringUtils.hasText(cmd.remark) ? cmd.remark.trim() : null);
        tenantMapper.insert(e);

        log.info("创建租户：tenantId={}, tenantCode={}", e.getId(), e.getTenantCode());
        return e;
    }

    @Transactional
    public TenantEntity update(UpdateCommand cmd) {
        TenantEntity e = tenantMapper.selectById(cmd.id);
        if (e == null) {
            throw new IllegalArgumentException("tenant not found");
        }

        if (StringUtils.hasText(cmd.name)) {
            e.setName(cmd.name.trim());
        }
        if (cmd.status != null) {
            e.setStatus(cmd.status);
        }
        if (cmd.siteRole != null) {
            e.setSiteRole(normalizeSiteRole(cmd.siteRole));
        }
        if (cmd.remark != null) {
            e.setRemark(StringUtils.hasText(cmd.remark) ? cmd.remark.trim() : null);
        }

        tenantMapper.updateById(e);
        log.info("更新租户：tenantId={}, tenantCode={}", e.getId(), e.getTenantCode());
        return e;
    }

    /**
     * 硬删除租户（物理删除）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该操作不可逆。</li>
     *   <li>如果该租户已被域名映射/业务数据引用，可能触发数据不一致；建议先禁用，再迁移数据后删除。</li>
     *   <li>目前 SQL 未设置外键约束，因此删除不会自动级联清理域名映射。</li>
     * </ul>
     */
    @Transactional
    public void delete(long id) {
        TenantEntity e = tenantMapper.selectById(id);
        if (e == null) {
            throw new IllegalArgumentException("tenant not found");
        }
        int rows = tenantMapper.deleteById(id);
        if (rows <= 0) {
            log.warn("删除租户失败：rows=0，tenantId={}, tenantCode={}", id, e.getTenantCode());
            throw new IllegalArgumentException("tenant not found");
        }
        log.info("删除租户：tenantId={}, tenantCode={}", id, e.getTenantCode());
    }

    public static class CreateCommand {
        public String tenantCode;
        public String name;
        public Integer status;
        public String siteRole;
        public String remark;
    }

    public static class UpdateCommand {
        public long id;
        public String name;
        public Integer status;
        public String siteRole;
        public String remark;
    }

    /**
     * 说明：
     * 站点定位统一在服务层做一次归一化，避免控制器、数据库脚本、前端枚举出现大小写漂移。
     */
    public static String normalizeSiteRole(String siteRole) {
        return PlatformTenantSettingsService.normalizeSiteRole(siteRole);
    }
}

