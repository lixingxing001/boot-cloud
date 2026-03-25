package com.bootcloud.auth.core.admin;

import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.auth.core.error.OAuthException;
import com.bootcloud.auth.infra.mybatis.entity.AdminAuthUserEntity;
import com.bootcloud.auth.infra.mybatis.mapper.AdminAuthUserMapper;
import com.bootcloud.auth.infra.mybatis.mapper.AdminPermissionMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

/**
 * 后台管理员账号密码认证器（用于 OAuth2 的 admin_password grant）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>管理员账号来源：共享后台账号表 {@code t_admin_user}。</li>
 *   <li>密码存储：BCrypt。</li>
 *   <li>后台管理员支持 tenant_id 与 scope_type 双层作用域，登录时优先匹配租户后台账号。</li>
 *   <li>若租户账号不存在，再回退匹配 SYSTEM 作用域账号，兼容平台超管登录。</li>
 * </ul>
 */
@Slf4j
public class AdminUserAuthenticator {

    private final AdminAuthUserMapper adminUserMapper;
    private final AdminPermissionMapper permissionMapper;
    private final PasswordEncoder passwordEncoder;

    public AdminUserAuthenticator(AdminAuthUserMapper adminUserMapper,
                                  AdminPermissionMapper permissionMapper,
                                  PasswordEncoder passwordEncoder) {
        this.adminUserMapper = adminUserMapper;
        this.permissionMapper = permissionMapper;
        this.passwordEncoder = passwordEncoder;
    }

    public AdminPrincipal authenticate(long tenantId, String username, String password) {
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw OAuthException.invalidRequest("missing username or password");
        }

        String input = username.trim();
        AdminAuthUserEntity systemAdmin = findSystemAdmin(input);
        AdminAuthUserEntity tenantAdmin = findTenantAdmin(tenantId, input);

        if (systemAdmin != null && systemAdmin.getId() != null && tenantAdmin != null && tenantAdmin.getId() != null) {
            log.warn("admin_password 命中同名账号冲突：username={}, requestTenantId={}, systemAdminId={}, tenantAdminId={}",
                    input, tenantId, systemAdmin.getId(), tenantAdmin.getId());
        }

        AdminAuthUserEntity admin = resolveMatchedAdmin(tenantId, input, password, systemAdmin, tenantAdmin);

        if (admin == null || admin.getId() == null) {
            if (isDisabledCandidateMatched(tenantId, input, password)) {
                log.warn("admin_password 登录失败：账号或角色已禁用，tenantId={}, username={}", tenantId, input);
                throw OAuthException.invalidGrant(CommonErrorCode.ACCOUNT_DISABLED.code());
            }
            log.info("admin_password 登录失败：管理员不存在或已禁用，tenantId={}, username={}", tenantId, input);
            throw OAuthException.invalidGrant("invalid username or password");
        }
        if (!StringUtils.hasText(admin.getPassword())) {
            log.warn("admin_password 登录失败：管理员密码为空（数据异常），adminId={}", admin.getId());
            throw OAuthException.invalidGrant("password is not set for this admin");
        }
        if (!passwordEncoder.matches(password, admin.getPassword())) {
            log.info("admin_password 登录失败：密码不匹配，adminId={}", admin.getId());
            throw OAuthException.invalidGrant("invalid username or password");
        }

        boolean systemAdminSession = isCompatibleSystemAdmin(admin, systemAdmin);
        long sessionTenantId = resolveSessionTenantId(admin, systemAdminSession);
        String resolvedScopeType = systemAdminSession ? "SYSTEM" : admin.getScopeType();

        // scope 由 grant 强制（OAuthService.grantAdminPassword），这里不做用户级 scope 限制
        log.info("admin_password 登录成功：adminId={}, tenantId={}, sessionTenantId={}, scopeType={}, username={}",
                admin.getId(), admin.getTenantId(), sessionTenantId, resolvedScopeType, admin.getUsername());
        return new AdminPrincipal(String.valueOf(admin.getId()), sessionTenantId, resolvedScopeType);
    }

    /**
     * 解析最终命中的后台管理员。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>当 SYSTEM 与 TENANT 作用域存在同名账号时，优先尝试 SYSTEM 管理员。</li>
     *   <li>只有 SYSTEM 账号密码不匹配时，才继续尝试当前租户下的 TENANT 账号。</li>
     *   <li>这样可以避免平台超管与租户管理员同名时，被误判成租户级登录态。</li>
     * </ul>
     */
    private AdminAuthUserEntity resolveMatchedAdmin(long tenantId,
                                                    String username,
                                                    String password,
                                                    AdminAuthUserEntity systemAdmin,
                                                    AdminAuthUserEntity tenantAdmin) {
        if (matchesPassword(systemAdmin, password)) {
            log.debug("admin_password 优先命中 SYSTEM 管理员：username={}, requestTenantId={}, adminId={}",
                    username, tenantId, systemAdmin.getId());
            return systemAdmin;
        }
        if (matchesPassword(tenantAdmin, password)) {
            log.debug("admin_password 命中 TENANT 管理员：username={}, requestTenantId={}, adminId={}",
                    username, tenantId, tenantAdmin.getId());
            return tenantAdmin;
        }
        if (systemAdmin != null && systemAdmin.getId() != null) {
            log.debug("admin_password SYSTEM 候选存在但密码不匹配：username={}, requestTenantId={}, adminId={}",
                    username, tenantId, systemAdmin.getId());
        }
        if (tenantAdmin != null && tenantAdmin.getId() != null) {
            log.debug("admin_password TENANT 候选存在但密码不匹配：username={}, requestTenantId={}, adminId={}",
                    username, tenantId, tenantAdmin.getId());
        }
        return systemAdmin != null ? systemAdmin : tenantAdmin;
    }

    private boolean matchesPassword(AdminAuthUserEntity admin, String password) {
        return admin != null
                && admin.getId() != null
                && StringUtils.hasText(admin.getPassword())
                && passwordEncoder.matches(password, admin.getPassword());
    }

    /**
     * 解析后台管理员的“会话租户”。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>SYSTEM 管理员的 token 会话固定落到 tenant_id=0。</li>
     *   <li>TENANT 管理员继续保留原租户归属，避免打穿租户边界。</li>
     * </ul>
     */
    private long resolveSessionTenantId(AdminAuthUserEntity admin, boolean systemAdminSession) {
        if (admin == null) {
            return 0L;
        }
        if (systemAdminSession || "SYSTEM".equalsIgnoreCase(admin.getScopeType())) {
            return 0L;
        }
        return admin.getTenantId() == null ? 0L : admin.getTenantId();
    }

    private AdminAuthUserEntity findSystemAdmin(String username) {
        return adminUserMapper.selectCompatibleSystemAdminByUsername(username);
    }

    private AdminAuthUserEntity findTenantAdmin(long tenantId, String username) {
        if (tenantId <= 0) {
            return null;
        }
        return adminUserMapper.selectTenantAdminByTenantIdAndUsername(tenantId, username);
    }

    /**
     * 检测“密码正确但账号/角色禁用”的候选，给前端返回明确禁用提示。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>只在密码命中时才返回 account_disabled，降低用户名探测风险。</li>
     *   <li>tenant 与 system 两类候选都做覆盖，避免同名账号导致误判。</li>
     * </ul>
     */
    private boolean isDisabledCandidateMatched(long tenantId, String username, String password) {
        AdminAuthUserEntity systemAdmin = adminUserMapper.selectCompatibleSystemAdminByUsernameIncludingDisabled(username);
        if (matchesDisabledCandidate(systemAdmin, password)) {
            log.debug("admin_password 命中禁用 SYSTEM 管理员：username={}, tenantId={}, adminId={}",
                    username, tenantId, systemAdmin.getId());
            return true;
        }

        if (tenantId <= 0) {
            return false;
        }
        AdminAuthUserEntity tenantAdmin = adminUserMapper.selectTenantAdminByTenantIdAndUsernameIncludingDisabled(tenantId, username);
        if (matchesDisabledCandidate(tenantAdmin, password)) {
            log.debug("admin_password 命中禁用 TENANT 管理员：username={}, tenantId={}, adminId={}",
                    username, tenantId, tenantAdmin.getId());
            return true;
        }
        return false;
    }

    private boolean matchesDisabledCandidate(AdminAuthUserEntity admin, String password) {
        if (admin == null || admin.getId() == null) {
            return false;
        }
        if (!StringUtils.hasText(admin.getPassword())) {
            return false;
        }
        if (!passwordEncoder.matches(password, admin.getPassword())) {
            return false;
        }
        return !isLoginEnabled(admin);
    }

    /**
     * 登录态可用判定：管理员账号与角色都必须启用。
     */
    private boolean isLoginEnabled(AdminAuthUserEntity admin) {
        if (admin == null) {
            return false;
        }
        return admin.getStatus() != null
                && admin.getStatus() == 1
                && admin.getRoleStatus() != null
                && admin.getRoleStatus() == 1;
    }

    /**
     * 判断当前登录命中的管理员，是否应按系统级管理员会话处理。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>优先信任“系统级候选命中”这条链路，便于排查同名账号冲突。</li>
     *   <li>同时兼容历史数据里只绑定 super_admin 角色，但用户 tenant_id / scope_type 尚未完全迁好的情况。</li>
     * </ul>
     */
    private boolean isCompatibleSystemAdmin(AdminAuthUserEntity admin, AdminAuthUserEntity systemAdminCandidate) {
        if (admin == null || admin.getId() == null) {
            return false;
        }
        if (systemAdminCandidate != null && systemAdminCandidate.getId() != null
                && systemAdminCandidate.getId().equals(admin.getId())) {
            if (log.isDebugEnabled()) {
                log.debug("admin_password 当前命中管理员按系统级会话处理：来源=system_candidate, adminId={}", admin.getId());
            }
            return true;
        }
        boolean compatibleSuperAdmin = permissionMapper.countCompatibleSuperAdminByAdminId(admin.getId()) > 0;
        if (compatibleSuperAdmin && log.isDebugEnabled()) {
            log.debug("admin_password 当前命中管理员按系统级会话处理：来源=legacy_super_admin_role, adminId={}", admin.getId());
        }
        return compatibleSuperAdmin;
    }
}
