package com.bootcloud.common.security.oauth2;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * OAuth2 资源服务通用配置。
 *
 * <p>调用认证中心所需的 client_id、client_secret、baseUrl 由 {@code boot.cloud.auth.client.*} 提供。</p>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.oauth2.resource-server")
public class OAuth2ResourceServerProperties {

    /**
     * 是否启用 OAuth2 资源服务鉴权（opaque token introspection）。
     *
     * <p>默认启用，避免服务长期处于未鉴权状态。</p>
     */
    private boolean enabled = true;

    /**
     * 默认租户 ID（当请求未携带租户头时兜底）。
     *
     * <p>请求未携带租户头时使用该值兜底。</p>
     */
    private long defaultTenantId = 1L;

    /**
     * 是否输出资源服务鉴权调试日志。
     *
     * <p>调试日志不输出 token 明文，只输出 traceId、tenantId、clientId 等关键信息。</p>
     */
    private boolean debugLog = false;

    /**
     * 是否启用 introspection 本地缓存。
     *
     * <ul>
     *   <li>默认启用，仅缓存 active=true 的自省结果。</li>
     *   <li>用于降低高并发下对认证中心的重复自省压力。</li>
     * </ul>
     */
    private boolean introspectionCacheEnabled = true;

    /**
     * introspection 本地缓存 TTL（秒）。
     *
     * <p>说明：最终 TTL 会与 token 剩余有效期取最小值。</p>
     */
    private long introspectionCacheTtlSeconds = 15L;

    /**
     * introspection 本地缓存最大条目数。
     */
    private int introspectionCacheMaxEntries = 20000;
}

