package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * boot-cloud-gateway 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>auth introspection 走 boot-cloud-auth 的 /oauth/check_token。</li>
 *   <li>租户解析默认走 boot-cloud-base 的 /internal/tenant/resolve，不信任客户端自带租户头。</li>
 *   <li>为了后续扩展（域名映射、多租户、白名单、缓存），网关把关键参数做成配置项。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.gateway")
public class GatewayProperties {

    /**
     * boot-cloud-base 服务名（用于域名解析 tenantId）。
     */
    private String baseServiceId = "boot-cloud-base";

    /**
     * 内部租户解析接口路径。
     */
    private String tenantResolvePath = "/internal/tenant/resolve";

    // 说明：
    // 网关调用 boot-cloud-auth 的 introspection 配置已迁移到 boot-cloud-starter-auth（推荐使用 boot.cloud.auth.client.*）。
    // 这样 gateway/web/业务服务可以统一使用同一套调用配置结构。

    /**
     * 不需要鉴权的路径（Ant 风格）。
     */
    private List<String> publicPaths = new ArrayList<>();

    /**
     * 兼容令牌模式开关。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于少量遗留客户端仍使用自定义令牌头的过渡场景。</li>
     *   <li>当前主链路已收敛为 Bearer 必传，该配置默认关闭。</li>
     * </ul>
     */
    private LegacyAuth legacy = new LegacyAuth();

    private String tenantHeader = "X-Tenant-Id";

    private String userIdHeader = "X-User-Id";

    private String clientIdHeader = "X-Client-Id";

    private String scopeHeader = "X-Scope";

    /**
     * 域名解析缓存 TTL（网关本地内存缓存，减少 boot-cloud-base 压力）。
     */
    private Duration tenantCacheTtl = Duration.ofSeconds(30);

    /**
     * 是否启用 token introspection 本地缓存。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认启用，减少高并发下每次请求都打 boot-cloud-auth /oauth/check_token 的压力。</li>
     *   <li>只缓存 active=true 的结果，失效后会自动回源自省。</li>
     * </ul>
     */
    private boolean introspectionCacheEnabled = true;

    /**
     * token introspection 本地缓存 TTL。
     *
     * <p>说明：最终 TTL 会与 token 剩余有效期取最小值，避免缓存超过 token 本身生命周期。</p>
     */
    private Duration introspectionCacheTtl = Duration.ofSeconds(15);

    /**
     * token introspection 本地缓存最大条目数。
     *
     * <p>说明：用于防止异常流量下缓存无限增长。</p>
     */
    private int introspectionCacheMaxEntries = 10000;

    /**
     * 是否允许信任客户端传入的租户头（X-Tenant-Id）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认 false：网关不信任客户端租户头，统一由网关解析并注入。</li>
     *   <li>仅用于应急回滚：若历史链路强依赖客户端租户头，可临时改为 true。</li>
     * </ul>
     */
    private boolean acceptTenantHeaderFromClient = false;

    /**
     * 是否信任上游透传的“原始访问域名”请求头。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认 false，防止客户端伪造 Header 影响租户解析。</li>
     *   <li>当前端域名与 API 域名分离时，可在“网关前置代理”注入可信头并启用该配置。</li>
     *   <li>建议仅在 Nginx/Ingress 会覆盖同名头的前提下开启。</li>
     * </ul>
     */
    private boolean trustForwardedHostHeaders = false;

    /**
     * 原始访问域名候选头（按优先级）。
     *
     * <p>说明：仅在 {@link #trustForwardedHostHeaders} 为 true 时生效。</p>
     */
    private List<String> forwardedHostHeaderCandidates = new ArrayList<>(List.of(
            "X-Forwarded-Host",
            "X-Original-Host",
            "Forwarded"
    ));

    /**
     * 域名解析失败时是否直接拒绝请求。
     *
     * <p>说明：默认 true（fail-closed），避免解析失败时错误落到默认租户。</p>
     */
    private boolean failOnTenantResolveError = true;

    /**
     * 当 Host 缺失时使用的默认 tenantId。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>当前实现会优先读取后台维护的运行时默认租户。</li>
     *   <li>这里保留为最后兜底值，用于 boot-cloud-base 或数据库异常时的紧急回退。</li>
     * </ul>
     */
    private long defaultTenantId = 1L;

    @Data
    public static class LegacyAuth {

        /**
         * 是否启用兼容令牌模式。
         */
        private boolean enabled = false;

        /**
         * 兼容模式下的 token 头名称。
         */
        private String tokenHeader = "satoken";

        /**
         * 兼容令牌模式下的受保护路径（Ant 风格）。
         */
        private List<String> legacyPaths = new ArrayList<>();
    }
}
