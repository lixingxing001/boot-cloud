package com.bootcloud.base.core.tenant.admin;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.bootcloud.base.infra.mybatis.entity.TenantDomainEntity;
import com.bootcloud.base.infra.mybatis.entity.TenantEntity;
import com.bootcloud.base.infra.mybatis.mapper.TenantDomainMapper;
import com.bootcloud.base.infra.mybatis.mapper.TenantMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * 域名映射管理（evm_tenant_domain）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该服务用于维护 “domain -> tenantId” 映射，供网关租户解析链路使用。</li>
 *   <li>domain 在写入时会做标准化（小写、去端口、拒绝带路径/协议），避免歧义。</li>
 * </ul>
 */
@Service
public class TenantDomainAdminService {

    private static final Logger log = LoggerFactory.getLogger(TenantDomainAdminService.class);

    private final TenantDomainMapper domainMapper;
    private final TenantMapper tenantMapper;

    public TenantDomainAdminService(TenantDomainMapper domainMapper, TenantMapper tenantMapper) {
        this.domainMapper = domainMapper;
        this.tenantMapper = tenantMapper;
    }

    public IPage<TenantDomainEntity> page(Long tenantId, String domainLike, Integer status, int pageNo, int pageSize) {
        LambdaQueryWrapper<TenantDomainEntity> qw = new LambdaQueryWrapper<TenantDomainEntity>()
                .orderByDesc(TenantDomainEntity::getId);
        if (tenantId != null) {
            qw.eq(TenantDomainEntity::getTenantId, tenantId);
        }
        if (StringUtils.hasText(domainLike)) {
            qw.like(TenantDomainEntity::getDomain, domainLike.trim().toLowerCase());
        }
        if (status != null) {
            qw.eq(TenantDomainEntity::getStatus, status);
        }
        return domainMapper.selectPage(new Page<>(pageNo, pageSize), qw);
    }

    public TenantDomainEntity get(long tenantId, long id) {
        TenantDomainEntity e = domainMapper.selectById(id);
        if (e == null || e.getTenantId() == null || e.getTenantId() != tenantId) {
            return null;
        }
        return e;
    }

    @Transactional
    public TenantDomainEntity create(CreateCommand cmd) {
        if (cmd.tenantId <= 0) {
            throw new IllegalArgumentException("tenant_id is required");
        }
        if (!StringUtils.hasText(cmd.domain)) {
            throw new IllegalArgumentException("domain is required");
        }

        // 校验 tenant 存在
        TenantEntity tenant = tenantMapper.selectById(cmd.tenantId);
        if (tenant == null) {
            throw new IllegalArgumentException("tenant not found");
        }

        String normalized = normalizeHost(cmd.domain);
        if (!StringUtils.hasText(normalized)) {
            throw new IllegalArgumentException("invalid domain");
        }

        TenantDomainEntity existed = domainMapper.selectOne(new LambdaQueryWrapper<TenantDomainEntity>()
                .eq(TenantDomainEntity::getDomain, normalized)
                .last("LIMIT 1"));
        if (existed != null) {
            throw new IllegalArgumentException("domain already exists");
        }

        TenantDomainEntity e = new TenantDomainEntity();
        e.setTenantId(cmd.tenantId);
        e.setDomain(normalized);
        e.setIsPrimary(cmd.isPrimary == null ? 0 : cmd.isPrimary);
        e.setStatus(cmd.status == null ? 1 : cmd.status);
        e.setRemark(StringUtils.hasText(cmd.remark) ? cmd.remark.trim() : null);

        domainMapper.insert(e);
        log.info("创建域名映射：tenantId={}, domain={}, id={}", e.getTenantId(), e.getDomain(), e.getId());
        return e;
    }

    @Transactional
    public TenantDomainEntity update(UpdateCommand cmd) {
        TenantDomainEntity e = get(cmd.tenantId, cmd.id);
        if (e == null) {
            throw new IllegalArgumentException("domain mapping not found");
        }

        // domain 允许更新，但需要重新做唯一性校验
        if (cmd.domain != null) {
            String normalized = normalizeHost(cmd.domain);
            if (!StringUtils.hasText(normalized)) {
                throw new IllegalArgumentException("invalid domain");
            }
            if (!normalized.equals(e.getDomain())) {
                TenantDomainEntity existed = domainMapper.selectOne(new LambdaQueryWrapper<TenantDomainEntity>()
                        .eq(TenantDomainEntity::getDomain, normalized)
                        .last("LIMIT 1"));
                if (existed != null) {
                    throw new IllegalArgumentException("domain already exists");
                }
                e.setDomain(normalized);
            }
        }
        if (cmd.isPrimary != null) {
            e.setIsPrimary(cmd.isPrimary);
        }
        if (cmd.status != null) {
            e.setStatus(cmd.status);
        }
        if (cmd.remark != null) {
            e.setRemark(StringUtils.hasText(cmd.remark) ? cmd.remark.trim() : null);
        }

        domainMapper.updateById(e);
        log.info("更新域名映射：tenantId={}, domain={}, id={}", cmd.tenantId, e.getDomain(), e.getId());
        return e;
    }

    @Transactional
    public void delete(long tenantId, long id) {
        TenantDomainEntity e = get(tenantId, id);
        if (e == null) {
            throw new IllegalArgumentException("domain mapping not found");
        }
        int rows = domainMapper.delete(new LambdaQueryWrapper<TenantDomainEntity>()
                .eq(TenantDomainEntity::getTenantId, tenantId)
                .eq(TenantDomainEntity::getId, id));
        if (rows <= 0) {
            log.warn("删除域名映射失败：rows=0，tenantId={}, domain={}, id={}", tenantId, e.getDomain(), id);
            throw new IllegalArgumentException("domain mapping not found");
        }
        log.info("删除域名映射：tenantId={}, domain={}, id={}", tenantId, e.getDomain(), id);
    }

    /**
     * host 标准化：只保留 hostname，转小写，去掉端口。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>与 {@code TenantResolveService} 保持一致，避免管理侧写入与解析侧读取不一致。</li>
     * </ul>
     */
    private static String normalizeHost(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String s = raw.trim().toLowerCase();
        int idx = s.indexOf(':');
        if (idx > 0) {
            s = s.substring(0, idx);
        }
        if (s.contains("/") || s.contains("://")) {
            return null;
        }
        return s;
    }

    public static class CreateCommand {
        public long tenantId;
        public String domain;
        public Integer isPrimary;
        public Integer status;
        public String remark;
    }

    public static class UpdateCommand {
        public long tenantId;
        public long id;
        public String domain;
        public Integer isPrimary;
        public Integer status;
        public String remark;
    }
}

