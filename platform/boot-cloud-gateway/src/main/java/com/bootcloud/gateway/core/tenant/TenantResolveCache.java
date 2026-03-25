package com.bootcloud.gateway.core.tenant;

import com.bootcloud.gateway.config.GatewayProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 域名 -> tenantId 的网关本地缓存（极简 TTL）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>减少每次请求都调用 boot-cloud-base 的压力。</li>
 *   <li>不引入额外依赖（例如 Caffeine），保持最小可用。</li>
 *   <li>后续如果需要更强的缓存能力（最大容量、统计、异步刷新），再替换实现即可。</li>
 * </ul>
 */
@Component
public class TenantResolveCache {

    private final Map<String, Entry> cache = new ConcurrentHashMap<>();
    private final Duration ttl;
    private final Clock clock;

    public TenantResolveCache(GatewayProperties properties) {
        this.ttl = properties.getTenantCacheTtl();
        this.clock = Clock.systemUTC();
    }

    public TenantResolveResponse get(String domain) {
        if (!StringUtils.hasText(domain)) {
            return null;
        }
        Entry e = cache.get(domain);
        if (e == null) {
            return null;
        }
        if (e.expiresAtMillis < clock.millis()) {
            cache.remove(domain);
            return null;
        }
        return e.value;
    }

    public void put(String domain, TenantResolveResponse value) {
        if (!StringUtils.hasText(domain) || value == null) {
            return;
        }
        long expiresAt = clock.millis() + Math.max(ttl.toMillis(), 1L);
        cache.put(domain, new Entry(value, expiresAt));
    }

    private record Entry(TenantResolveResponse value, long expiresAtMillis) {
    }
}

