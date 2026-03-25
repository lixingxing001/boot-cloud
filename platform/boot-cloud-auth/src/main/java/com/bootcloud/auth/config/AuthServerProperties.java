package com.bootcloud.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 认证中心配置。
 *
 * <p>该配置只保留脚手架真正需要的通用能力：</p>
 * <ul>
 *   <li>租户访问控制</li>
 *   <li>OAuth2 client 与开发期内置账号</li>
 *   <li>权限缓存与系统级 client 优先级</li>
 *   <li>多会话、设备会话与 MFA</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.auth")
public class AuthServerProperties {

    /**
     * 允许访问的租户白名单。
     *
     * <p>留空表示不做白名单限制。</p>
     */
    private List<Long> allowedTenantIds = new ArrayList<>();

    /**
     * 禁止访问的租户黑名单。
     */
    private List<Long> deniedTenantIds = new ArrayList<>();

    /**
     * 默认 access_token 有效期，单位秒。
     */
    private long defaultAccessTokenTtlSeconds = 7200;

    /**
     * 默认 refresh_token 有效期，单位秒。
     */
    private long defaultRefreshTokenTtlSeconds = 2592000;

    /**
     * authorization_code 有效期，单位秒。
     */
    private long authorizationCodeTtlSeconds = 300;

    /**
     * 是否复用 refresh_token。
     */
    private boolean reuseRefreshToken = true;

    /**
     * 是否启用开发期内置账号。
     */
    private boolean devUsersEnabled = false;

    /**
     * 静态 OAuth2 client 配置。
     */
    private List<ClientConfig> clients = new ArrayList<>();

    /**
     * 开发期内置账号列表。
     */
    private List<DevUserConfig> devUsers = new ArrayList<>();

    /**
     * 管理端权限缓存配置。
     */
    private AdminAuthoritiesConfig adminAuthorities = new AdminAuthoritiesConfig();

    /**
     * 多会话配置。
     */
    private MultiSessionConfig multiSession = new MultiSessionConfig();

    /**
     * 设备会话配置。
     */
    private DeviceSessionConfig deviceSession = new DeviceSessionConfig();

    /**
     * 登录 MFA 配置。
     */
    private MfaLoginConfig mfaLogin = new MfaLoginConfig();

    /**
     * OAuth2 client 缓存配置。
     */
    private ClientCacheConfig clientCache = new ClientCacheConfig();

    /**
     * 系统级 client 优先命中策略。
     */
    private SystemClientPreferenceConfig systemClientPreference = new SystemClientPreferenceConfig();

    @Data
    public static class ClientConfig {
        /** 所属租户。 */
        private long tenantId;
        /** client_id。 */
        private String clientId;
        /** BCrypt 后的 client_secret。 */
        private String clientSecretHash;
        /** 允许的 grant_type 列表。 */
        private List<String> grantTypes = new ArrayList<>();
        /** 允许的 scope 列表。 */
        private List<String> scopes = new ArrayList<>();
        /** 允许的 redirect_uri 列表。 */
        private List<String> redirectUris = new ArrayList<>();
        /** access_token 有效期覆盖值。 */
        private Long accessTokenTtlSeconds;
        /** refresh_token 有效期覆盖值。 */
        private Long refreshTokenTtlSeconds;
        /** 是否允许签发 refresh_token。 */
        private Boolean allowRefreshToken;
        /** 是否启用。 */
        private boolean enabled = true;
    }

    @Data
    public static class DevUserConfig {
        /** 所属租户。 */
        private long tenantId;
        /** 登录用户名。 */
        private String username;
        /** BCrypt 后的登录密码。 */
        private String passwordHash;
        /** 逻辑用户 ID。 */
        private String userId;
        /** 默认 scope 列表。 */
        private List<String> scopes = new ArrayList<>();
        /** 是否启用。 */
        private boolean enabled = true;
    }

    @Data
    public static class AdminAuthoritiesConfig {
        /** 是否启用权限缓存。 */
        private boolean enabled = true;
        /** 权限缓存 TTL，单位秒。 */
        private long cacheTtlSeconds = 90;
    }

    @Data
    public static class MultiSessionConfig {
        /** 是否启用多会话。 */
        private boolean enabled = true;
        /** 启用多会话索引隔离的 client_id 列表。 */
        private List<String> clientIds = new ArrayList<>(List.of("boot-cloud-admin-web", "boot-cloud-web"));
        /** deviceId 参数名。 */
        private String deviceIdParamName = "device_id";
        /** deviceId 最大长度。 */
        private int maxDeviceIdLength = 64;
    }

    @Data
    public static class DeviceSessionConfig {
        /** 是否启用设备会话。 */
        private boolean enabled = true;
        /** 记录保留时长，单位秒。 */
        private long ttlSeconds = 7776000L;
        /** 单用户设备上限。 */
        private int maxDevicesPerUser = 20;
        /** 超限策略。 */
        private String overflowPolicy = "reject_new";
        /** 按 clientId 覆盖的设备策略。 */
        private Map<String, DeviceSessionClientConfig> clients = new LinkedHashMap<>();

        public String normalizedOverflowPolicy() {
            String policy = overflowPolicy == null ? "" : overflowPolicy.trim().toLowerCase(Locale.ROOT);
            if ("kick_oldest".equals(policy)) {
                return "kick_oldest";
            }
            return "reject_new";
        }

        public static boolean isSupportedOverflowPolicy(String raw) {
            if (raw == null || raw.trim().isEmpty()) {
                return true;
            }
            String policy = raw.trim().toLowerCase(Locale.ROOT);
            return "reject_new".equals(policy) || "kick_oldest".equals(policy);
        }
    }

    @Data
    public static class DeviceSessionClientConfig {
        /** 是否覆盖启用状态。 */
        private Boolean enabled;
        /** 是否覆盖 TTL。 */
        private Long ttlSeconds;
        /** 是否覆盖设备上限。 */
        private Integer maxDevicesPerUser;
        /** 是否覆盖超限策略。 */
        private String overflowPolicy;

        public String normalizedOverflowPolicy(String fallback) {
            if (overflowPolicy == null || overflowPolicy.trim().isEmpty()) {
                return fallback;
            }
            String policy = overflowPolicy.trim().toLowerCase(Locale.ROOT);
            if ("kick_oldest".equals(policy)) {
                return "kick_oldest";
            }
            return "reject_new";
        }
    }

    @Data
    public static class ResolvedDeviceSessionConfig {
        /** 当前 client 的最终启用状态。 */
        private boolean enabled;
        /** 当前 client 的最终 TTL。 */
        private long ttlSeconds;
        /** 当前 client 的最终设备上限。 */
        private int maxDevicesPerUser;
        /** 当前 client 的最终超限策略。 */
        private String overflowPolicy;
        /** 是否命中 client 级覆盖。 */
        private boolean clientOverrideApplied;
    }

    @Data
    public static class MfaLoginConfig {
        /** 登录模式。 */
        private String mode = "strict";
        /** 固定验证码，仅 fixed_otp 模式使用。 */
        private String fixedOtp = "";
        /** 非 strict 模式是否仅允许在开发环境使用。 */
        private boolean devOnly = true;
        /** 允许启用弱校验模式的 profile 列表。 */
        private List<String> allowedProfiles = new ArrayList<>(List.of("local", "dev", "test"));

        public String normalizedMode() {
            return mode == null ? "strict" : mode.trim().toLowerCase(Locale.ROOT);
        }
    }

    @Data
    public static class ClientCacheConfig {
        /** 是否启用 client 信息缓存。 */
        private boolean enabled = true;
        /** 正向缓存 TTL，单位秒。 */
        private long ttlSeconds = 120;
        /** 是否启用空结果短缓存。 */
        private boolean negativeEnabled = false;
        /** 负缓存 TTL，单位秒。 */
        private long negativeTtlSeconds = 10;
    }

    @Data
    public static class SystemClientPreferenceConfig {
        /** 是否启用系统级 client 优先命中。 */
        private boolean enabled = true;
        /** 优先走 SYSTEM 作用域的 client_id 列表。 */
        private List<String> clientIds = new ArrayList<>(List.of(
                "boot-cloud-gateway",
                "boot-cloud-resource-server",
                "boot-cloud-realtime"
        ));
    }

    /**
     * 获取最终生效的多会话配置。
     */
    public MultiSessionConfig effectiveMultiSession() {
        return multiSession != null ? multiSession : new MultiSessionConfig();
    }

    /**
     * 获取按 clientId 解析后的设备会话策略。
     */
    public ResolvedDeviceSessionConfig effectiveDeviceSession(String clientId) {
        DeviceSessionConfig base = deviceSession != null ? deviceSession : new DeviceSessionConfig();
        ResolvedDeviceSessionConfig resolved = new ResolvedDeviceSessionConfig();
        resolved.setEnabled(base.isEnabled());
        resolved.setTtlSeconds(base.getTtlSeconds());
        resolved.setMaxDevicesPerUser(base.getMaxDevicesPerUser());
        resolved.setOverflowPolicy(base.normalizedOverflowPolicy());
        resolved.setClientOverrideApplied(false);

        if (clientId == null || clientId.trim().isEmpty() || base.getClients() == null || base.getClients().isEmpty()) {
            return resolved;
        }

        DeviceSessionClientConfig override = findDeviceSessionClientOverride(base.getClients(), clientId);
        if (override == null) {
            return resolved;
        }

        if (override.getEnabled() != null) {
            resolved.setEnabled(override.getEnabled());
        }
        if (override.getTtlSeconds() != null) {
            resolved.setTtlSeconds(override.getTtlSeconds());
        }
        if (override.getMaxDevicesPerUser() != null) {
            resolved.setMaxDevicesPerUser(override.getMaxDevicesPerUser());
        }
        resolved.setOverflowPolicy(override.normalizedOverflowPolicy(resolved.getOverflowPolicy()));
        resolved.setClientOverrideApplied(true);
        return resolved;
    }

    /**
     * 获取最终生效的系统级 client 偏好配置。
     */
    public SystemClientPreferenceConfig effectiveSystemClientPreference() {
        return systemClientPreference != null ? systemClientPreference : new SystemClientPreferenceConfig();
    }

    private static DeviceSessionClientConfig findDeviceSessionClientOverride(
            Map<String, DeviceSessionClientConfig> clientConfigs,
            String clientId
    ) {
        if (clientConfigs == null || clientConfigs.isEmpty() || clientId == null || clientId.trim().isEmpty()) {
            return null;
        }
        String normalizedClientId = clientId.trim();
        DeviceSessionClientConfig direct = clientConfigs.get(normalizedClientId);
        if (direct != null) {
            return direct;
        }
        for (Map.Entry<String, DeviceSessionClientConfig> entry : clientConfigs.entrySet()) {
            if (entry.getKey() != null && normalizedClientId.equals(entry.getKey().trim())) {
                return entry.getValue();
            }
        }
        return null;
    }
}
