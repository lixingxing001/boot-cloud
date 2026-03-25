package com.bootcloud.auth.core.admin;

/**
 * 后台管理员认证结果。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>系统级管理员与租户级管理员都共用 admin_password grant。</li>
 *   <li>为了让系统级管理员会话固定落到 tenant_id=0，这里显式返回“会话租户”。</li>
 *   <li>下游签发 token、刷新 token、撤销 token 时都应以 sessionTenantId 为准。</li>
 * </ul>
 */
public record AdminPrincipal(
        String userId,
        long sessionTenantId,
        String scopeType
) {

    /**
     * 是否系统级管理员。
     */
    public boolean isSystemScope() {
        return "SYSTEM".equalsIgnoreCase(scopeType);
    }
}
