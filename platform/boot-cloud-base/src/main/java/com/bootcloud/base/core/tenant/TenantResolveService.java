package com.bootcloud.base.core.tenant;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.bootcloud.base.config.BaseProperties;
import com.bootcloud.base.core.tenant.admin.PlatformTenantSettingsService;
import com.bootcloud.base.infra.mybatis.entity.TenantDomainEntity;
import com.bootcloud.base.infra.mybatis.mapper.TenantDomainMapper;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * 域名解析 tenantId 的服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>网关将 Host 传入本服务，本服务返回 tenantId。</li>
 *   <li>默认租户由配置与运行时设置共同决定，同时保留按域名映射租户的扩展能力。</li>
 * </ul>
 */
@Service
public class TenantResolveService {

    private final TenantDomainMapper tenantDomainMapper;
    private final BaseProperties properties;
    private final PlatformTenantSettingsService platformTenantSettingsService;

    public TenantResolveService(
            TenantDomainMapper tenantDomainMapper,
            BaseProperties properties,
            PlatformTenantSettingsService platformTenantSettingsService
    ) {
        this.tenantDomainMapper = tenantDomainMapper;
        this.properties = properties;
        this.platformTenantSettingsService = platformTenantSettingsService;
    }

    public TenantResolveResult resolveByDomain(String domain) {
        String normalized = normalizeHost(domain);
        if (!StringUtils.hasText(normalized)) {
            return defaultResult(domain);
        }

        TenantDomainEntity hit = tenantDomainMapper.selectOne(new LambdaQueryWrapper<TenantDomainEntity>()
                .eq(TenantDomainEntity::getDomain, normalized)
                .eq(TenantDomainEntity::getStatus, 1)
                .last("LIMIT 1"));

        if (hit == null || hit.getTenantId() == null || hit.getTenantId() <= 0) {
            if (properties.isFailOnNotFound()) {
                throw new IllegalArgumentException("domain not mapped: " + normalized);
            }
            return defaultResult(normalized);
        }

        return TenantResolveResult.of(hit.getTenantId(), normalized, false);
    }

    private TenantResolveResult defaultResult(String domain) {
        long defaultTenantId = platformTenantSettingsService.resolveDefaultTenantId();
        return TenantResolveResult.of(defaultTenantId, normalizeHost(domain), true);
    }

    /**
     * host 标准化：只保留 hostname，转小写，去掉端口。
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
        // 极简校验：避免传入 URL/路径
        if (s.contains("/") || s.contains("://")) {
            return null;
        }
        return s;
    }
}
