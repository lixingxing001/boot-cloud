package com.bootcloud.common.core.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * SecurityUserUtils 与上下文 Filter 的配置项。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>默认按网关的注入头读取用户信息：X-User-Id、X-Tenant-Id、X-Client-Id、X-Scope。</li>
 *   <li>scope 支持两种分隔符：空格、逗号。</li>
 *   <li>生产环境建议关闭 debug 日志，避免日志噪声。</li>
 * </ul>
 *
 * <p>示例（Nacos 或 application.yml）：</p>
 * <pre>
 * boot:
 *   cloud:
 *     security:
 *       user:
 *         enabled: true
 *         debug-log: false
 *         user-id-header: X-User-Id
 *         tenant-id-header: X-Tenant-Id
 *         client-id-header: X-Client-Id
 *         scope-header: X-Scope
 * </pre>
 */
@ConfigurationProperties(prefix = "boot.cloud.security.user")
public class SecurityUserProperties {

    /**
     * 是否启用用户上下文 Filter。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认启用，方便业务代码通过 SecurityUserUtils 获取 userId tenantId。</li>
     *   <li>如某些服务完全不需要此能力，可设置为 false。</li>
     * </ul>
     */
    private boolean enabled = true;

    /**
     * 是否输出调试日志。
     *
     * <p>说明：只输出 userId tenantId clientId scopes，不输出 token。</p>
     */
    private boolean debugLog = false;

    /**
     * 用户 ID Header 名称。
     */
    private String userIdHeader = "X-User-Id";

    /**
     * 租户 ID Header 名称。
     */
    private String tenantIdHeader = "X-Tenant-Id";

    /**
     * client_id Header 名称。
     */
    private String clientIdHeader = "X-Client-Id";

    /**
     * scope Header 名称。
     */
    private String scopeHeader = "X-Scope";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isDebugLog() {
        return debugLog;
    }

    public void setDebugLog(boolean debugLog) {
        this.debugLog = debugLog;
    }

    public String getUserIdHeader() {
        return userIdHeader;
    }

    public void setUserIdHeader(String userIdHeader) {
        this.userIdHeader = userIdHeader;
    }

    public String getTenantIdHeader() {
        return tenantIdHeader;
    }

    public void setTenantIdHeader(String tenantIdHeader) {
        this.tenantIdHeader = tenantIdHeader;
    }

    public String getClientIdHeader() {
        return clientIdHeader;
    }

    public void setClientIdHeader(String clientIdHeader) {
        this.clientIdHeader = clientIdHeader;
    }

    public String getScopeHeader() {
        return scopeHeader;
    }

    public void setScopeHeader(String scopeHeader) {
        this.scopeHeader = scopeHeader;
    }
}
