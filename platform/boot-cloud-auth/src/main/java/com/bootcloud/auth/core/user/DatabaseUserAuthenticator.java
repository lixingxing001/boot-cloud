package com.bootcloud.auth.core.user;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.bootcloud.auth.core.error.OAuthException;
import com.bootcloud.auth.infra.mybatis.entity.AuthUser;
import com.bootcloud.auth.infra.mybatis.entity.UserMfaBackupCodeEntity;
import com.bootcloud.auth.infra.mybatis.entity.UserMfaTotpEntity;
import com.bootcloud.auth.infra.mybatis.mapper.AuthUserMapper;
import com.bootcloud.auth.infra.mybatis.mapper.UserMfaBackupCodeMapper;
import com.bootcloud.auth.infra.mybatis.mapper.UserMfaTotpMapper;
import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.common.core.security.TotpUtil;
import cn.dev33.satoken.context.SaHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 从共享用户表 {@code t_user} 进行用户名/密码校验，用于 OAuth2 的 password grant。
 *
 * <p>这样设计的原因：</p>
 * <ul>
 *   <li>脚手架默认复用业务系统已有用户表，降低重复建模成本。</li>
 *   <li>当前实现假设 boot-cloud-auth 与用户域服务共用同一个数据库。</li>
 * </ul>
 *
 * <p>多租户说明（重要）：</p>
 * <ul>
 *   <li>当前实现已经切换为按 {@code tenant_id + username/email} 查询用户。</li>
 *   <li>登录二次验证（TOTP / 备份码）同样按 {@code tenant_id + user_id} 校验，避免多租户串用同一份 MFA 数据。</li>
 * </ul>
 */
@Slf4j
public class DatabaseUserAuthenticator implements UserAuthenticator {

    private final AuthUserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final UserMfaTotpMapper totpMapper;
    private final UserMfaBackupCodeMapper backupCodeMapper;
    private final AuthServerProperties properties;
    private final Environment environment;

    public DatabaseUserAuthenticator(
            AuthUserMapper userMapper,
            PasswordEncoder passwordEncoder,
            UserMfaTotpMapper totpMapper,
            UserMfaBackupCodeMapper backupCodeMapper,
            AuthServerProperties properties,
            Environment environment
    ) {
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.totpMapper = totpMapper;
        this.backupCodeMapper = backupCodeMapper;
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public UserPrincipal authenticatePassword(long tenantId, String username, String password) {
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw OAuthException.invalidRequest("missing username or password");
        }

        // 兼容现有用户域服务：用户可能通过用户名或邮箱登录
        AuthUser user = findUserByUsernameOrEmail(tenantId, username.trim());
        if (user == null || user.getId() == null) {
            log.warn("password grant 登录失败：用户不存在，tenantId={}, username={}", tenantId, maskLoginIdentifier(username));
            throw OAuthException.invalidGrant("invalid username or password");
        }
        if (!StringUtils.hasText(user.getPassword())) {
            // 兼容无密码用户：password grant 不允许通过
            log.warn("password grant 登录失败：用户未设置密码，tenantId={}, userId={}", tenantId, user.getId());
            throw OAuthException.invalidGrant("password is not set for this user");
        }
        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("password grant 登录失败：密码不匹配，tenantId={}, userId={}", tenantId, user.getId());
            throw OAuthException.invalidGrant("invalid username or password");
        }

        // 说明：如果用户启用了 TOTP 二次验证，则 password grant 需要额外校验一次性验证码或备份码
        verifyLoginMfaIfEnabled(tenantId, user.getId());

        // scope 暂不做“用户级”限制（由 client 的 scopes 控制）。
        log.info("password grant 登录成功：tenantId={}, userId={}", tenantId, user.getId());
        return new UserPrincipal(String.valueOf(user.getId()), Collections.emptySet());
    }

    @Override
    public void verifyLoginMfaIfEnabled(long tenantId, long userId) {
        verifyMfaIfEnabled(tenantId, userId);
    }

    private void verifyMfaIfEnabled(Long tenantId, Long userId) {
        if (userId == null || userId <= 0) {
            return;
        }
        if (tenantId == null || tenantId <= 0) {
            throw OAuthException.invalidRequest("missing tenant_id");
        }
        if (totpMapper == null) {
            return;
        }
        UserMfaTotpEntity cfg = totpMapper.selectOne(new LambdaQueryWrapper<UserMfaTotpEntity>()
                .eq(UserMfaTotpEntity::getDeleted, 0)
                .eq(UserMfaTotpEntity::getTenantId, tenantId)
                .eq(UserMfaTotpEntity::getUserId, userId)
                .eq(UserMfaTotpEntity::getEnabled, 1)
                .last("LIMIT 1"));
        if (cfg == null || !StringUtils.hasText(cfg.getSecretBase32())) {
            return;
        }

        AuthServerProperties.MfaLoginConfig mfaCfg = properties == null ? null : properties.getMfaLogin();
        String mode = mfaCfg == null ? "strict" : mfaCfg.normalizedMode();

        if ("bypass".equals(mode)) {
            log.warn("MFA 登录校验已绕过：mode=bypass, userId={}, activeProfiles={}", userId, resolveActiveProfiles());
            return;
        }

        String otp = resolveParam("otp");
        String backupCode = resolveParam("backup_code");
        if ("fixed_otp".equals(mode)) {
            String fixedOtp = mfaCfg == null || mfaCfg.getFixedOtp() == null ? "" : mfaCfg.getFixedOtp().trim();
            if (!StringUtils.hasText(fixedOtp)) {
                log.error("MFA fixed_otp 配置异常：fixedOtp 为空，userId={}", userId);
                throw OAuthException.invalidGrant("mfa_fixed_otp_not_configured");
            }
            // 说明：fixed_otp 联调模式下也允许使用备份码，避免前端切到“备份码登录”时被误判 otp_required。
            if (StringUtils.hasText(backupCode)) {
                if (consumeBackupCodeIfMatch(tenantId, userId, backupCode.trim())) {
                    log.warn("MFA 登录使用备份码：mode=fixed_otp, tenantId={}, userId={}, activeProfiles={}", tenantId, userId, resolveActiveProfiles());
                    return;
                }
                throw OAuthException.invalidGrant("invalid_backup_code");
            }
            if (!StringUtils.hasText(otp)) {
                throw OAuthException.invalidGrant("otp_required");
            }
            if (!fixedOtp.equals(otp.trim())) {
                throw OAuthException.invalidGrant("invalid_otp");
            }
            log.warn("MFA 登录使用固定验证码：mode=fixed_otp, tenantId={}, userId={}, activeProfiles={}", tenantId, userId, resolveActiveProfiles());
            return;
        }

        if (StringUtils.hasText(otp)) {
            boolean ok = TotpUtil.verifyCode(cfg.getSecretBase32(), otp, System.currentTimeMillis(), 1);
            if (!ok) {
                throw OAuthException.invalidGrant("invalid_otp");
            }
            return;
        }

        if (StringUtils.hasText(backupCode)) {
            if (consumeBackupCodeIfMatch(tenantId, userId, backupCode.trim())) {
                return;
            }
            throw OAuthException.invalidGrant("invalid_backup_code");
        }

        throw OAuthException.invalidGrant("otp_required");
    }

    /**
     * 读取当前激活 profile 集合。
     */
    private String resolveActiveProfiles() {
        if (environment == null || environment.getActiveProfiles() == null) {
            return "[]";
        }
        Set<String> profiles = java.util.Arrays.stream(environment.getActiveProfiles())
                .filter(StringUtils::hasText)
                .map(p -> p.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        return profiles.toString();
    }

    private boolean consumeBackupCodeIfMatch(long tenantId, long userId, String input) {
        if (backupCodeMapper == null || passwordEncoder == null) {
            return false;
        }
        List<UserMfaBackupCodeEntity> list = backupCodeMapper.selectList(new LambdaQueryWrapper<UserMfaBackupCodeEntity>()
                .eq(UserMfaBackupCodeEntity::getDeleted, 0)
                .eq(UserMfaBackupCodeEntity::getTenantId, tenantId)
                .eq(UserMfaBackupCodeEntity::getUserId, userId)
                .eq(UserMfaBackupCodeEntity::getUsed, 0));
        if (list == null || list.isEmpty()) {
            return false;
        }
        for (UserMfaBackupCodeEntity e : list) {
            if (e == null || !StringUtils.hasText(e.getCodeHash())) {
                continue;
            }
            if (passwordEncoder.matches(input, e.getCodeHash())) {
                e.setUsed(1);
                e.setUsedAt(LocalDateTime.now());
                backupCodeMapper.updateById(e);
                return true;
            }
        }
        return false;
    }

    private static String resolveParam(String name) {
        try {
            return SaHolder.getRequest().getParam(name);
        } catch (Exception e) {
            return null;
        }
    }

    private AuthUser findUserByUsernameOrEmail(long tenantId, String input) {
        boolean looksLikeEmail = input.contains("@");
        if (looksLikeEmail) {
            AuthUser byEmail = selectByEmail(tenantId, input);
            if (byEmail != null) return byEmail;
            // 邮箱输入也允许兜底按 username 查（避免历史数据特殊）
            return selectByUsername(tenantId, input);
        }

        AuthUser byUsername = selectByUsername(tenantId, input);
        if (byUsername != null) return byUsername;
        // 兼容：部分前端可能把 email 填进 username 字段
        return selectByEmail(tenantId, input);
    }

    private AuthUser selectByUsername(long tenantId, String username) {
        LambdaQueryWrapper<AuthUser> qw = new LambdaQueryWrapper<AuthUser>()
                .eq(AuthUser::getDeleted, 0)
                .eq(AuthUser::getTenantId, tenantId)
                .eq(AuthUser::getUsername, username)
                .select(AuthUser::getId, AuthUser::getPassword);
        return userMapper.selectOne(qw);
    }

    private AuthUser selectByEmail(long tenantId, String email) {
        LambdaQueryWrapper<AuthUser> qw = new LambdaQueryWrapper<AuthUser>()
                .eq(AuthUser::getDeleted, 0)
                .eq(AuthUser::getTenantId, tenantId)
                .eq(AuthUser::getEmail, email)
                .select(AuthUser::getId, AuthUser::getPassword);
        return userMapper.selectOne(qw);
    }

    private static String maskLoginIdentifier(String raw) {
        if (!StringUtils.hasText(raw)) {
            return "";
        }
        String v = raw.trim();
        if (v.contains("@")) {
            int at = v.indexOf('@');
            if (at <= 1) {
                return "***";
            }
            return v.substring(0, 1) + "***" + v.substring(at);
        }
        if (v.length() <= 8) {
            return "****";
        }
        return v.substring(0, 2) + "****" + v.substring(v.length() - 2);
    }
}
