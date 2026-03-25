package com.bootcloud.auth.core.user;

public interface UserAuthenticator {
    UserPrincipal authenticatePassword(long tenantId, String username, String password);

    /**
     * 校验用户是否需要并通过登录二次验证。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认实现为空，兼容仅做账号密码校验的实现。</li>
     *   <li>业务服务 数据库实现会覆盖该方法，统一校验 otp 或 backup_code。</li>
     * </ul>
     */
    default void verifyLoginMfaIfEnabled(long tenantId, long userId) {
        // 默认无操作
    }
}

