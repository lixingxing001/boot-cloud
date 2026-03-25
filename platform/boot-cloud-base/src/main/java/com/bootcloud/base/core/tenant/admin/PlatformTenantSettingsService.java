package com.bootcloud.base.core.tenant.admin;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.bootcloud.base.config.BaseProperties;
import com.bootcloud.base.infra.mybatis.entity.SystemConfigEntity;
import com.bootcloud.base.infra.mybatis.entity.TenantEntity;
import com.bootcloud.base.infra.mybatis.mapper.SystemConfigMapper;
import com.bootcloud.base.infra.mybatis.mapper.TenantMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Objects;

/**
 * 平台租户运行时设置服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>默认租户改为优先读数据库，Nacos 只保留启动兜底值。</li>
 *   <li>默认租户只允许指向“主入口站点”且启用的租户，降低误切换风险。</li>
 * </ul>
 */
@Slf4j
@Service
public class PlatformTenantSettingsService {

    public static final String CONFIG_KEY_DEFAULT_TENANT_ID = "platform.default_tenant_id";
    public static final String SITE_ROLE_PRIMARY_PORTAL = "PRIMARY_PORTAL";
    public static final String SITE_ROLE_BUSINESS_SITE = "BUSINESS_SITE";
    private static final String DEFAULT_TENANT_CONFIG_DESCRIPTION = "平台默认租户ID，由后台系统设置维护";
    private static final long CACHE_TTL_MILLIS = 5_000L;

    private final SystemConfigMapper systemConfigMapper;
    private final TenantMapper tenantMapper;
    private final BaseProperties properties;

    private volatile CachedDefaultTenant cachedDefaultTenant;

    public PlatformTenantSettingsService(
            SystemConfigMapper systemConfigMapper,
            TenantMapper tenantMapper,
            BaseProperties properties
    ) {
        this.systemConfigMapper = systemConfigMapper;
        this.tenantMapper = tenantMapper;
        this.properties = properties;
    }

    /**
     * 获取当前默认租户快照。
     */
    public DefaultTenantSnapshot getDefaultTenantSnapshot() {
        CachedDefaultTenant cached = cachedDefaultTenant;
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAt() > now) {
            return cached.snapshot();
        }

        synchronized (this) {
            cached = cachedDefaultTenant;
            if (cached != null && cached.expiresAt() > now) {
                return cached.snapshot();
            }
            DefaultTenantSnapshot loaded = loadDefaultTenantSnapshot();
            cachedDefaultTenant = new CachedDefaultTenant(loaded, now + CACHE_TTL_MILLIS);
            return loaded;
        }
    }

    /**
     * 当前默认租户 ID。
     */
    public long resolveDefaultTenantId() {
        return getDefaultTenantSnapshot().tenantId();
    }

    /**
     * 更新平台默认租户。
     */
    @Transactional(rollbackFor = Exception.class)
    public DefaultTenantSnapshot updateDefaultTenant(long tenantId) {
        if (tenantId <= 0) {
            throw new IllegalArgumentException("tenantId 必须大于 0");
        }
        TenantEntity tenant = tenantMapper.selectById(tenantId);
        if (tenant == null || tenant.getId() == null) {
            throw new IllegalArgumentException("目标租户不存在");
        }
        if (tenant.getStatus() == null || tenant.getStatus() != 1) {
            throw new IllegalArgumentException("只有启用状态的租户才能设为默认租户");
        }
        String siteRole = normalizeSiteRole(tenant.getSiteRole());
        if (!SITE_ROLE_PRIMARY_PORTAL.equals(siteRole)) {
            throw new IllegalArgumentException("只有主入口站点类型的租户才能设为默认租户");
        }

        systemConfigMapper.upsertConfig(
                CONFIG_KEY_DEFAULT_TENANT_ID,
                String.valueOf(tenantId),
                DEFAULT_TENANT_CONFIG_DESCRIPTION
        );
        cachedDefaultTenant = null;

        DefaultTenantSnapshot snapshot = getDefaultTenantSnapshot();
        log.info("平台默认租户更新完成: tenantId={}, tenantCode={}, siteRole={}",
                snapshot.tenantId(), snapshot.tenantCode(), snapshot.siteRole());
        return snapshot;
    }

    /**
     * 统一规范化站点定位。
     */
    public static String normalizeSiteRole(String siteRole) {
        if (!StringUtils.hasText(siteRole)) {
            return SITE_ROLE_BUSINESS_SITE;
        }
        String normalized = siteRole.trim().toUpperCase();
        if (SITE_ROLE_PRIMARY_PORTAL.equals(normalized)) {
            return SITE_ROLE_PRIMARY_PORTAL;
        }
        return SITE_ROLE_BUSINESS_SITE;
    }

    private DefaultTenantSnapshot loadDefaultTenantSnapshot() {
        SystemConfigEntity config = systemConfigMapper.selectOne(new LambdaQueryWrapper<SystemConfigEntity>()
                .eq(SystemConfigEntity::getConfigKey, CONFIG_KEY_DEFAULT_TENANT_ID)
                .last("LIMIT 1"));

        Long configuredTenantId = parseTenantId(config == null ? null : config.getConfigValue());
        boolean configured = configuredTenantId != null && configuredTenantId > 0;
        long fallbackTenantId = properties.getDefaultTenantId() > 0 ? properties.getDefaultTenantId() : 1L;
        long tenantId = configured ? configuredTenantId : fallbackTenantId;

        TenantEntity tenant = tenantMapper.selectById(tenantId);
        if (tenant == null || tenant.getId() == null) {
            throw new IllegalStateException("平台默认租户不存在，请检查配置: tenantId=" + tenantId);
        }

        return new DefaultTenantSnapshot(
                tenant.getId(),
                tenant.getTenantCode(),
                tenant.getName(),
                normalizeSiteRole(tenant.getSiteRole()),
                tenant.getStatus(),
                configured,
                configured ? "DB" : "NACOS_FALLBACK",
                Instant.now().toEpochMilli()
        );
    }

    private static Long parseTenantId(String raw) {
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

    private record CachedDefaultTenant(DefaultTenantSnapshot snapshot, long expiresAt) {
    }

    /**
     * 平台默认租户快照。
     */
    public record DefaultTenantSnapshot(
            long tenantId,
            String tenantCode,
            String tenantName,
            String siteRole,
            Integer status,
            boolean configured,
            String source,
            long resolvedAt
    ) {
        public boolean sameTenant(Long tenantId) {
            return tenantId != null && Objects.equals(this.tenantId, tenantId);
        }
    }
}
