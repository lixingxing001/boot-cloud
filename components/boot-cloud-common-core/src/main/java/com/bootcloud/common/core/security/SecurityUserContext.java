package com.bootcloud.common.core.security;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 当前请求的用户上下文（线程内有效）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当前阶段：主要来源是网关注入的 Header，例如 X-User-Id、X-Tenant-Id、X-Scope。</li>
 *   <li>未来阶段：当业务服务升级为标准 OAuth2 资源服务后，用户信息也可能来自 Spring Security 的认证上下文。</li>
 *   <li>本类只保存“业务常用字段”，避免在业务层到处解析 Header。</li>
 * </ul>
 */
public class SecurityUserContext {

    /**
     * 用户 ID（字符串形态，便于兼容不同来源）。
     */
    private final String userId;

    /**
     * 租户 ID（字符串形态）。
     */
    private final String tenantId;

    /**
     * OAuth2 client_id。
     */
    private final String clientId;

    /**
     * scope 集合。
     */
    private final Set<String> scopes;

    public SecurityUserContext(String userId, String tenantId, String clientId, Set<String> scopes) {
        this.userId = trimToNull(userId);
        this.tenantId = trimToNull(tenantId);
        this.clientId = trimToNull(clientId);
        this.scopes = scopes == null ? Collections.emptySet() : Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
    }

    public String getUserId() {
        return userId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public boolean hasScope(String scope) {
        if (scope == null || scope.isBlank()) return false;
        return scopes.contains(scope.trim());
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String v = s.trim();
        return v.isEmpty() ? null : v;
    }
}
