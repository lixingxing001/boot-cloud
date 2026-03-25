package com.bootcloud.auth.core.tenant;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.bootcloud.auth.infra.mybatis.entity.SystemConfigEntity;
import com.bootcloud.auth.infra.mybatis.mapper.SystemConfigMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * 平台默认租户读取服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot-cloud-auth 只负责读取后台维护的默认租户配置，用于放行当前有效租户头。</li>
 *   <li>这里做短缓存，避免每次授权请求都打数据库。</li>
 * </ul>
 */
@Slf4j
@Service
public class PlatformDefaultTenantService {

    public static final String CONFIG_KEY_DEFAULT_TENANT_ID = "platform.default_tenant_id";
    private static final long CACHE_TTL_MILLIS = 5_000L;

    private final SystemConfigMapper systemConfigMapper;

    private volatile CachedTenantId cachedTenantId;

    public PlatformDefaultTenantService(SystemConfigMapper systemConfigMapper) {
        this.systemConfigMapper = systemConfigMapper;
    }

    /**
     * 读取当前平台默认租户 ID。
     *
     * @return 成功返回默认租户 ID，读取失败或未配置返回 null
     */
    public Long getRuntimeDefaultTenantId() {
        CachedTenantId cached = cachedTenantId;
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAt() > now) {
            return cached.tenantId();
        }

        synchronized (this) {
            cached = cachedTenantId;
            if (cached != null && cached.expiresAt() > now) {
                return cached.tenantId();
            }
            Long loaded = loadTenantId();
            cachedTenantId = new CachedTenantId(loaded, now + CACHE_TTL_MILLIS);
            return loaded;
        }
    }

    private Long loadTenantId() {
        try {
            SystemConfigEntity config = systemConfigMapper.selectOne(new LambdaQueryWrapper<SystemConfigEntity>()
                    .eq(SystemConfigEntity::getConfigKey, CONFIG_KEY_DEFAULT_TENANT_ID)
                    .last("LIMIT 1"));
            Long tenantId = parseTenantId(config == null ? null : config.getConfigValue());
            if (tenantId != null && tenantId > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("boot-cloud-auth 读取平台默认租户成功: tenantId={}, source=DB", tenantId);
                }
                return tenantId;
            }
            if (log.isDebugEnabled()) {
                log.debug("boot-cloud-auth 未读取到平台默认租户配置，回退配置白名单");
            }
            return null;
        } catch (Exception e) {
            log.warn("boot-cloud-auth 读取平台默认租户失败，将回退配置白名单: msg={}", e.getMessage());
            return null;
        }
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

    private record CachedTenantId(Long tenantId, long expiresAt) {
    }
}
