package com.bootcloud.auth.config;

import com.bootcloud.auth.core.client.ClientRegistry;
import com.bootcloud.auth.core.client.DbClientRegistry;
import com.bootcloud.auth.core.admin.AdminUserAuthenticator;
import com.bootcloud.auth.core.tenant.PlatformDefaultTenantService;
import com.bootcloud.auth.core.tenant.TenantResolver;
import com.bootcloud.auth.core.tenant.HeaderTenantResolver;
import com.bootcloud.auth.core.user.DatabaseUserAuthenticator;
import com.bootcloud.auth.core.user.UserAuthenticator;
import com.bootcloud.auth.infra.mybatis.mapper.AuthUserMapper;
import com.bootcloud.auth.infra.mybatis.mapper.AdminAuthUserMapper;
import com.bootcloud.auth.infra.mybatis.mapper.AdminPermissionMapper;
import com.bootcloud.auth.infra.mybatis.mapper.OAuthClientMapper;
import com.bootcloud.auth.infra.mybatis.mapper.UserMfaBackupCodeMapper;
import com.bootcloud.auth.infra.mybatis.mapper.UserMfaTotpMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@EnableConfigurationProperties(AuthServerProperties.class)
public class AuthServerConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TenantResolver tenantResolver(AuthServerProperties properties, PlatformDefaultTenantService platformDefaultTenantService) {
        return new HeaderTenantResolver(properties, platformDefaultTenantService);
    }

    @Bean
    public ClientRegistry clientRegistry(OAuthClientMapper clientMapper, PasswordEncoder passwordEncoder) {
        // client 从数据库读取，便于后续在控制台统一治理与动态下发。
        return new DbClientRegistry(clientMapper, passwordEncoder);
    }

    @Bean
    public UserAuthenticator userAuthenticator(
            AuthUserMapper authUserMapper,
            PasswordEncoder passwordEncoder,
            UserMfaTotpMapper userMfaTotpMapper,
            UserMfaBackupCodeMapper userMfaBackupCodeMapper,
            AuthServerProperties properties,
            Environment environment
    ) {
        validateMfaLoginModeSafety(properties, environment);
        validateDeviceSessionConfig(properties);
        // 默认使用数据库账号体系做用户名密码校验。
        // 这里保留独立认证器接口，后续接入 LDAP、外部 IdP 或更多认证源时可以直接扩展。
        return new DatabaseUserAuthenticator(
                authUserMapper,
                passwordEncoder,
                userMfaTotpMapper,
                userMfaBackupCodeMapper,
                properties,
                environment
        );
    }

    @Bean
    public AdminUserAuthenticator adminUserAuthenticator(AdminAuthUserMapper adminAuthUserMapper,
                                                         AdminPermissionMapper adminPermissionMapper,
                                                         PasswordEncoder passwordEncoder) {
        // 管理端账号与权限查询独立于普通用户认证，便于后续切分后台安全域。
        return new AdminUserAuthenticator(adminAuthUserMapper, adminPermissionMapper, passwordEncoder);
    }

    /**
     * 启动时校验 MFA 登录模式安全性。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>strict 模式始终允许。</li>
     *   <li>fixed_otp / bypass 默认只允许在 local/dev/test profile。</li>
     *   <li>若 profile 不允许，直接启动失败，避免误把弱校验带到生产。</li>
     * </ul>
     */
    private static void validateMfaLoginModeSafety(AuthServerProperties properties, Environment environment) {
        AuthServerProperties.MfaLoginConfig cfg = properties.getMfaLogin();
        String mode = cfg == null ? "strict" : cfg.normalizedMode();
        if (!List.of("strict", "fixed_otp", "bypass").contains(mode)) {
            throw new IllegalStateException("boot.cloud.auth.mfa-login.mode 配置非法，仅支持 strict/fixed_otp/bypass");
        }
        if ("fixed_otp".equals(mode)) {
            String fixedOtp = cfg.getFixedOtp() == null ? "" : cfg.getFixedOtp().trim();
            if (fixedOtp.isEmpty()) {
                throw new IllegalStateException("boot.cloud.auth.mfa-login.fixed-otp 不能为空（mode=fixed_otp）");
            }
        }
        if ("strict".equals(mode) || cfg == null || !cfg.isDevOnly()) {
            log.info("MFA 登录模式已启用：mode={}, devOnly={}", mode, cfg != null && cfg.isDevOnly());
            return;
        }

        List<String> activeProfiles = Arrays.stream(environment.getActiveProfiles())
                .map(p -> p == null ? "" : p.trim().toLowerCase(Locale.ROOT))
                .filter(p -> !p.isEmpty())
                .collect(Collectors.toList());
        List<String> allowedProfiles = (cfg.getAllowedProfiles() == null ? List.<String>of() : cfg.getAllowedProfiles())
                .stream()
                .map(p -> p == null ? "" : p.trim().toLowerCase(Locale.ROOT))
                .filter(p -> !p.isEmpty())
                .collect(Collectors.toList());

        boolean profileAllowed = !activeProfiles.isEmpty() && activeProfiles.stream().anyMatch(allowedProfiles::contains);
        if (!profileAllowed) {
            throw new IllegalStateException(
                    "当前 profile 不允许使用非 strict 的 MFA 登录模式。activeProfiles=" + activeProfiles + ", allowedProfiles=" + allowedProfiles
            );
        }

        log.warn("MFA 登录模式为非 strict：mode={}, activeProfiles={}", mode, activeProfiles);
    }

    /**
     * 启动时校验设备会话限制配置。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>max-devices-per-user 允许配置为 -1/0 表示不限制，>0 表示严格上限。</li>
     *   <li>overflow-policy 仅支持 reject_new 或 kick_oldest。</li>
     * </ul>
     */
    private static void validateDeviceSessionConfig(AuthServerProperties properties) {
        if (properties == null || properties.getDeviceSession() == null) {
            return;
        }
        AuthServerProperties.DeviceSessionConfig cfg = properties.getDeviceSession();
        validateSingleDeviceSessionConfig(
                "boot.cloud.auth.device-session",
                cfg.getMaxDevicesPerUser(),
                cfg.getOverflowPolicy()
        );
        if (cfg.getClients() != null && !cfg.getClients().isEmpty()) {
            for (Map.Entry<String, AuthServerProperties.DeviceSessionClientConfig> entry : cfg.getClients().entrySet()) {
                String clientId = entry.getKey() == null ? "" : entry.getKey().trim();
                if (clientId.isEmpty()) {
                    throw new IllegalStateException("boot.cloud.auth.device-session.clients 存在空 clientId 配置，请检查");
                }
                AuthServerProperties.DeviceSessionClientConfig override = entry.getValue();
                if (override == null) {
                    continue;
                }
                validateSingleDeviceSessionConfig(
                        "boot.cloud.auth.device-session.clients." + clientId,
                        override.getMaxDevicesPerUser(),
                        override.getOverflowPolicy()
                );
                log.info("设备会话客户端覆盖配置已加载：clientId={}, enabled={}, ttlSeconds={}, maxDevicesPerUser={}, overflowPolicy={}",
                        clientId,
                        override.getEnabled(),
                        override.getTtlSeconds(),
                        override.getMaxDevicesPerUser(),
                        override.getOverflowPolicy());
            }
        }
        log.info("设备会话限制配置已启用：enabled={}, maxDevicesPerUser={}, overflowPolicy={}",
                cfg.isEnabled(), cfg.getMaxDevicesPerUser(), cfg.normalizedOverflowPolicy());
    }

    /**
     * 校验单个设备会话配置片段。
     */
    private static void validateSingleDeviceSessionConfig(String path, Integer maxDevicesPerUser, String overflowPolicy) {
        if (maxDevicesPerUser != null && maxDevicesPerUser < -1) {
            throw new IllegalStateException(path + ".max-devices-per-user 配置非法，允许 -1/0/正整数");
        }
        if (!AuthServerProperties.DeviceSessionConfig.isSupportedOverflowPolicy(overflowPolicy)) {
            throw new IllegalStateException(path + ".overflow-policy 配置非法，仅支持 reject_new/kick_oldest");
        }
    }
}
