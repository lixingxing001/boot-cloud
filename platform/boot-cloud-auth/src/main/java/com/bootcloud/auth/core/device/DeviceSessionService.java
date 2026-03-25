package com.bootcloud.auth.core.device;

import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Util;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.infra.satoken.oauth2.SaOAuth2Template;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * 设备会话服务：记录与查询“登录设备”，并支持远程登出。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>设备会话只记录必要的可观测信息，不保存 token 明文。</li>
 *   <li>远程登出通过“读取指定 deviceId 的 token index → 撤销 token”完成。</li>
 * </ul>
 */
@Slf4j
@Service
public class DeviceSessionService {

    private static final String KEY_PREFIX = "bootcloud:oauth2sess:";
    private static final String POLICY_REJECT_NEW = "reject_new";
    private static final String POLICY_KICK_OLDEST = "kick_oldest";

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final SaOAuth2Template saOAuth2Template;
    private final AuthServerProperties properties;

    public DeviceSessionService(
            StringRedisTemplate redis,
            ObjectMapper objectMapper,
            SaOAuth2Template saOAuth2Template,
            AuthServerProperties properties
    ) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.saOAuth2Template = saOAuth2Template;
        this.properties = properties;
    }

    /**
     * 签发 token 前的设备上限校验。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>当 maxDevicesPerUser <= 0 时，视为不限制。</li>
     *   <li>当当前 deviceId 已存在于设备列表中时，不计入“新设备登录”。</li>
     *   <li>超限时按 overflowPolicy 执行：reject_new 或 kick_oldest。</li>
     * </ul>
     */
    public DeviceLimitCheckResult preCheckBeforeTokenIssue(long tenantId, String clientId, long userId, String grantType) {
        if (tenantId <= 0 || userId <= 0 || !StringUtils.hasText(clientId)) {
            return DeviceLimitCheckResult.allow("invalid_input", null, 0, null, null);
        }
        AuthServerProperties.ResolvedDeviceSessionConfig effectiveConfig = effectiveDeviceSession(clientId);
        if (!effectiveConfig.isEnabled()) {
            return DeviceLimitCheckResult.allow("device_session_disabled", null, 0, null, null);
        }

        String deviceId = resolveDeviceId();
        if (!StringUtils.hasText(deviceId)) {
            // 说明：deviceId 缺失时保持兼容放行，避免影响老客户端登录。
            log.warn("设备上限校验跳过：deviceId 缺失，tenantId={}, clientId={}, userId={}, grantType={}",
                    tenantId, clientId, userId, safe(grantType));
            return DeviceLimitCheckResult.allow("device_id_missing", null, 0, null, null);
        }

        int max = effectiveMaxDevices(effectiveConfig);
        if (max <= 0) {
            return DeviceLimitCheckResult.allow("unlimited", null, max, deviceId, null);
        }

        String zKey = devicesZsetKey(tenantId, userId, clientId);
        String policy = effectiveOverflowPolicy(effectiveConfig);
        try {
            Double exists = redis.opsForZSet().score(zKey, deviceId);
            if (exists != null) {
                return DeviceLimitCheckResult.allow("same_device", policy, max, deviceId, null);
            }

            Long size = redis.opsForZSet().zCard(zKey);
            long count = size == null ? 0L : size;
            if (count < max) {
                return DeviceLimitCheckResult.allow("under_limit", policy, max, deviceId, null);
            }

            if (POLICY_KICK_OLDEST.equals(policy)) {
                String oldestDeviceId = findOldestDeviceId(zKey);
                if (!StringUtils.hasText(oldestDeviceId)) {
                    log.warn("设备上限触发但未找到最旧设备，降级为拒绝新登录：tenantId={}, clientId={}, userId={}, currentDevice={}, max={}",
                            tenantId, clientId, userId, maskDeviceId(deviceId), max);
                    return DeviceLimitCheckResult.reject("limit_reached_and_no_oldest", policy, max, deviceId, null);
                }
                if (oldestDeviceId.equals(deviceId)) {
                    // 理论上不会发生（前面已判断 same_device），这里保守放行并打日志。
                    log.warn("设备上限校验命中同设备异常分支：tenantId={}, clientId={}, userId={}, deviceId={}, max={}",
                            tenantId, clientId, userId, maskDeviceId(deviceId), max);
                    return DeviceLimitCheckResult.allow("same_device_unexpected_branch", policy, max, deviceId, null);
                }

                RevokeByDeviceResult kickResult = revokeByDevice(tenantId, clientId, userId, oldestDeviceId);
                log.info("设备上限触发并踢出最旧设备：tenantId={}, clientId={}, userId={}, currentDevice={}, kickedDevice={}, revokedAccess={}, revokedRefresh={}, removedFromSessionList={}, max={}",
                        tenantId, clientId, userId, maskDeviceId(deviceId), maskDeviceId(oldestDeviceId),
                        kickResult.revokedAccessToken(), kickResult.revokedRefreshToken(), kickResult.removedFromSessionList(), max);
                return DeviceLimitCheckResult.allow("kicked_oldest", policy, max, deviceId, oldestDeviceId);
            }

            log.warn("设备上限触发并拒绝新登录：tenantId={}, clientId={}, userId={}, currentDevice={}, activeDeviceCount={}, max={}",
                    tenantId, clientId, userId, maskDeviceId(deviceId), count, max);
            return DeviceLimitCheckResult.reject("limit_reached", policy, max, deviceId, null);
        } catch (Exception e) {
            // 说明：设备上限校验异常时默认放行，避免登录核心链路可用性受损。
            log.warn("设备上限校验异常，降级放行：tenantId={}, clientId={}, userId={}, deviceId={}, msg={}",
                    tenantId, clientId, userId, maskDeviceId(deviceId), e.getMessage());
            return DeviceLimitCheckResult.allow("check_failed_fallback_allow", policy, max, deviceId, null);
        }
    }

    /**
     * 记录设备会话（在签发 token 成功后调用）。
     */
    public void recordOnTokenIssued(long tenantId, String clientId, long userId, String grantType) {
        if (tenantId <= 0 || userId <= 0 || !StringUtils.hasText(clientId)) {
            return;
        }
        AuthServerProperties.ResolvedDeviceSessionConfig effectiveConfig = effectiveDeviceSession(clientId);
        if (!effectiveConfig.isEnabled()) {
            return;
        }

        String deviceId = resolveDeviceId();
        if (!StringUtils.hasText(deviceId)) {
            // deviceId 缺失时不记录，避免“设备列表”污染为同一条空 device 记录
            if (log.isDebugEnabled()) {
                log.debug("设备会话记录跳过：deviceId 缺失，tenantId={}, clientId={}, userId={}", tenantId, clientId, userId);
            }
            return;
        }

        String ua = resolveClientUserAgent();
        String ip = resolveClientIp();
        long now = System.currentTimeMillis();

        String zKey = devicesZsetKey(tenantId, userId, clientId);
        String metaKey = deviceMetaKey(tenantId, userId, clientId, deviceId);

        try {
            // 1) 更新排序集合（最近活跃优先）
            redis.opsForZSet().add(zKey, deviceId, now);

            // 2) 读取旧 meta，用于保留 firstSeenAt
            DeviceSessionMeta meta = null;
            String old = redis.opsForValue().get(metaKey);
            if (StringUtils.hasText(old)) {
                try {
                    meta = objectMapper.readValue(old, DeviceSessionMeta.class);
                } catch (Exception ignore) {
                    meta = null;
                }
            }
            if (meta == null) {
                meta = new DeviceSessionMeta();
                meta.setDeviceId(deviceId);
                meta.setFirstSeenAt(now);
            }
            meta.setLastSeenAt(now);
            meta.setLastGrantType(safe(grantType));
            if (StringUtils.hasText(ua)) {
                meta.setUserAgent(truncate(ua, 256));
            }
            if (StringUtils.hasText(ip)) {
                meta.setIp(truncate(ip, 64));
            }

            String json = objectMapper.writeValueAsString(meta);
            redis.opsForValue().set(metaKey, json);

            long ttl = effectiveTtlSeconds(effectiveConfig);
            if (ttl > 0) {
                redis.expire(zKey, ttl, TimeUnit.SECONDS);
                redis.expire(metaKey, ttl, TimeUnit.SECONDS);
            }

            // 3) 按 maxDevices 裁剪
            int max = effectiveMaxDevices(effectiveConfig);
            if (max > 0) {
                Long size = redis.opsForZSet().zCard(zKey);
                if (size != null && size > max) {
                    long removeCount = size - max;
                    // 删除最旧的 removeCount 条
                    Set<String> toRemove = redis.opsForZSet().range(zKey, 0, removeCount - 1);
                    if (toRemove != null && !toRemove.isEmpty()) {
                        redis.opsForZSet().remove(zKey, toRemove.toArray());
                        for (String d : toRemove) {
                            if (StringUtils.hasText(d)) {
                                redis.delete(deviceMetaKey(tenantId, userId, clientId, d));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("记录设备会话失败：tenantId={}, clientId={}, userId={}, msg={}", tenantId, clientId, userId, e.getMessage());
        }
    }

    public List<DeviceSessionView> listSessions(long tenantId, String clientId, long userId, int limit) {
        if (tenantId <= 0 || userId <= 0 || !StringUtils.hasText(clientId)) {
            return Collections.emptyList();
        }
        int lim = Math.max(limit, 1);
        String zKey = devicesZsetKey(tenantId, userId, clientId);
        try {
            Set<String> deviceIds = redis.opsForZSet().reverseRange(zKey, 0, lim - 1);
            if (deviceIds == null || deviceIds.isEmpty()) {
                return Collections.emptyList();
            }

            List<DeviceSessionView> out = new ArrayList<>();
            for (String deviceId : deviceIds) {
                if (!StringUtils.hasText(deviceId)) {
                    continue;
                }
                String metaKey = deviceMetaKey(tenantId, userId, clientId, deviceId);
                String json = redis.opsForValue().get(metaKey);
                DeviceSessionMeta meta = null;
                if (StringUtils.hasText(json)) {
                    try {
                        meta = objectMapper.readValue(json, DeviceSessionMeta.class);
                    } catch (Exception ignore) {
                        meta = null;
                    }
                }

                DeviceSessionView v = new DeviceSessionView();
                v.setDeviceId(deviceId);
                v.setFirstSeenAt(meta != null ? meta.getFirstSeenAt() : null);
                v.setLastSeenAt(meta != null ? meta.getLastSeenAt() : null);
                v.setUserAgent(meta != null ? meta.getUserAgent() : null);
                v.setIpMasked(maskIp(meta != null ? meta.getIp() : null));
                v.setLastGrantType(meta != null ? meta.getLastGrantType() : null);
                out.add(v);
            }
            return out;
        } catch (Exception e) {
            log.warn("查询设备会话失败：tenantId={}, clientId={}, userId={}, msg={}", tenantId, clientId, userId, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * 远程登出指定设备：撤销该 deviceId 下的 access_token 与 refresh_token（如果存在）。
     */
    public RevokeByDeviceResult revokeByDevice(long tenantId, String clientId, long userId, String rawDeviceId) {
        if (tenantId <= 0 || userId <= 0 || !StringUtils.hasText(clientId) || !StringUtils.hasText(rawDeviceId)) {
            return new RevokeByDeviceResult(false, false, false);
        }
        String deviceId = rawDeviceId.trim();

        boolean revokedAccess = false;
        boolean revokedRefresh = false;

        try {
            // 说明：按 index key 读取 token 值，不需要保存 token 明文到业务表
            String accessToken = saOAuth2Template.getAccessTokenValueByDevice(clientId, userId, deviceId);
            String refreshToken = saOAuth2Template.getRefreshTokenValueByDevice(clientId, userId, deviceId);

            if (StringUtils.hasText(accessToken)) {
                SaOAuth2Util.revokeAccessToken(accessToken.trim());
                revokedAccess = true;
            }
            if (StringUtils.hasText(refreshToken)) {
                SaOAuth2Util.saOAuth2Template.deleteRefreshToken(refreshToken.trim());
                revokedRefresh = true;
            }
            // 兜底：清理 index key（避免 index 残留影响后续）
            saOAuth2Template.deleteTokenIndexByDevice(clientId, userId, deviceId);
        } catch (Exception e) {
            log.warn("撤销设备 token 失败：tenantId={}, clientId={}, userId={}, deviceId={}, msg={}",
                    tenantId, clientId, userId, maskDeviceId(deviceId), e.getMessage());
        }

        // 清理设备会话记录
        boolean removed = removeDeviceSession(tenantId, clientId, userId, deviceId);

        return new RevokeByDeviceResult(removed, revokedAccess, revokedRefresh);
    }

    /**
     * 仅移除设备会话记录，不触发 token 撤销。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于“当前设备登出”后从设备列表中移除该设备。</li>
     *   <li>token 撤销由 /oauth/revoke 完成。</li>
     * </ul>
     */
    public boolean removeSessionRecordOnly(long tenantId, String clientId, long userId, String rawDeviceId) {
        if (tenantId <= 0 || userId <= 0 || !StringUtils.hasText(clientId) || !StringUtils.hasText(rawDeviceId)) {
            return false;
        }
        return removeDeviceSession(tenantId, clientId, userId, rawDeviceId.trim());
    }

    private boolean removeDeviceSession(long tenantId, String clientId, long userId, String deviceId) {
        String zKey = devicesZsetKey(tenantId, userId, clientId);
        String metaKey = deviceMetaKey(tenantId, userId, clientId, deviceId);
        try {
            redis.opsForZSet().remove(zKey, deviceId);
            redis.delete(metaKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private long effectiveTtlSeconds(AuthServerProperties.ResolvedDeviceSessionConfig effectiveConfig) {
        if (effectiveConfig == null) {
            return 0;
        }
        return Math.max(effectiveConfig.getTtlSeconds(), 0);
    }

    private int effectiveMaxDevices(AuthServerProperties.ResolvedDeviceSessionConfig effectiveConfig) {
        if (effectiveConfig == null) {
            return 0;
        }
        int raw = effectiveConfig.getMaxDevicesPerUser();
        // 说明：0/-1 都视为不限制。
        return raw <= 0 ? 0 : raw;
    }

    private String effectiveOverflowPolicy(AuthServerProperties.ResolvedDeviceSessionConfig effectiveConfig) {
        if (effectiveConfig == null || !StringUtils.hasText(effectiveConfig.getOverflowPolicy())) {
            return POLICY_REJECT_NEW;
        }
        return effectiveConfig.getOverflowPolicy();
    }

    /**
     * 读取指定 clientId 的最终设备会话配置，并输出调试日志，方便联调定位。
     */
    private AuthServerProperties.ResolvedDeviceSessionConfig effectiveDeviceSession(String clientId) {
        if (properties == null) {
            AuthServerProperties.ResolvedDeviceSessionConfig fallback = new AuthServerProperties.ResolvedDeviceSessionConfig();
            fallback.setEnabled(true);
            fallback.setTtlSeconds(0);
            fallback.setMaxDevicesPerUser(0);
            fallback.setOverflowPolicy(POLICY_REJECT_NEW);
            fallback.setClientOverrideApplied(false);
            return fallback;
        }
        AuthServerProperties.ResolvedDeviceSessionConfig effectiveConfig = properties.effectiveDeviceSession(clientId);
        if (log.isDebugEnabled()) {
            log.debug("设备会话生效配置解析完成：clientId={}, enabled={}, ttlSeconds={}, maxDevicesPerUser={}, overflowPolicy={}, overrideApplied={}",
                    clientId,
                    effectiveConfig.isEnabled(),
                    effectiveConfig.getTtlSeconds(),
                    effectiveConfig.getMaxDevicesPerUser(),
                    effectiveConfig.getOverflowPolicy(),
                    effectiveConfig.isClientOverrideApplied());
        }
        return effectiveConfig;
    }

    private String findOldestDeviceId(String zKey) {
        if (!StringUtils.hasText(zKey)) {
            return null;
        }
        Set<String> oldest = redis.opsForZSet().range(zKey, 0, 0);
        if (oldest == null || oldest.isEmpty()) {
            return null;
        }
        for (String candidate : oldest) {
            if (StringUtils.hasText(candidate)) {
                return candidate.trim();
            }
        }
        return null;
    }

    private static String resolveDeviceId() {
        try {
            String v = SaHolder.getRequest().getParam("device_id");
            if (StringUtils.hasText(v)) {
                return safeDeviceId(v.trim());
            }
            String h = SaHolder.getRequest().getHeader("X-Device-Id");
            if (StringUtils.hasText(h)) {
                return safeDeviceId(h.trim());
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String resolveClientUserAgent() {
        try {
            String v = SaHolder.getRequest().getHeader("X-Client-User-Agent");
            if (StringUtils.hasText(v)) {
                return v.trim();
            }
            return SaHolder.getRequest().getHeader("User-Agent");
        } catch (Exception e) {
            return null;
        }
    }

    private static String resolveClientIp() {
        try {
            String v = SaHolder.getRequest().getHeader("X-Client-IP");
            if (StringUtils.hasText(v)) {
                return v.trim();
            }
            String xff = SaHolder.getRequest().getHeader("X-Forwarded-For");
            if (StringUtils.hasText(xff)) {
                return xff.split(",")[0].trim();
            }
            return SaHolder.getRequest().getHeader("X-Real-IP");
        } catch (Exception e) {
            return null;
        }
    }

    private static String devicesZsetKey(long tenantId, long userId, String clientId) {
        return KEY_PREFIX + tenantId + ":u:" + userId + ":c:" + clientId.trim() + ":devz";
    }

    private static String deviceMetaKey(long tenantId, long userId, String clientId, String deviceId) {
        return KEY_PREFIX + tenantId + ":u:" + userId + ":c:" + clientId.trim() + ":dev:" + deviceId.trim();
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        int m = Math.max(max, 1);
        if (s.length() <= m) return s;
        return s.substring(0, m);
    }

    private static String safeDeviceId(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String v = raw.trim();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '_' || c == '-' || c == '.';
            if (ok) sb.append(c);
        }
        String out = sb.toString();
        if (!StringUtils.hasText(out)) {
            return null;
        }
        // 限制长度，避免 Key 过长
        return out.length() <= 64 ? out : out.substring(0, 64);
    }

    private static String maskIp(String ip) {
        if (!StringUtils.hasText(ip)) return "";
        String v = ip.trim();
        int idx = v.lastIndexOf('.');
        if (idx > 0) {
            return v.substring(0, idx) + ".*";
        }
        return v;
    }

    private static String maskDeviceId(String deviceId) {
        if (!StringUtils.hasText(deviceId)) {
            return "";
        }
        String v = deviceId.trim();
        if (v.length() <= 8) {
            return v;
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    @Data
    public static class DeviceSessionMeta {
        /**
         * deviceId（用于同账号多端同时在线的索引隔离）。
         */
        private String deviceId;

        /**
         * 首次看到该设备的时间（epochMs）。
         */
        private Long firstSeenAt;

        /**
         * 最近活跃时间（epochMs）。
         */
        private Long lastSeenAt;

        /**
         * 客户端 User-Agent（来自 BFF 透传）。
         */
        private String userAgent;

        /**
         * 客户端 IP（来自 BFF 透传，建议仅用于脱敏展示与排障）。
         */
        private String ip;

        /**
         * 最近一次签发 token 的 grant_type。
         */
        private String lastGrantType;
    }

    @Data
    public static class DeviceSessionView {
        private String deviceId;
        private Long firstSeenAt;
        private Long lastSeenAt;
        private String userAgent;
        private String ipMasked;
        private String lastGrantType;

        public String firstSeenAtIso() {
            if (firstSeenAt == null) return "";
            return Instant.ofEpochMilli(firstSeenAt).toString();
        }

        public String lastSeenAtIso() {
            if (lastSeenAt == null) return "";
            return Instant.ofEpochMilli(lastSeenAt).toString();
        }
    }

    public record RevokeByDeviceResult(boolean removedFromSessionList, boolean revokedAccessToken, boolean revokedRefreshToken) {
    }

    public record DeviceLimitCheckResult(
            boolean allowed,
            String reason,
            String policy,
            int maxDevices,
            String currentDeviceId,
            String affectedDeviceId
    ) {
        public static DeviceLimitCheckResult allow(
                String reason,
                String policy,
                int maxDevices,
                String currentDeviceId,
                String affectedDeviceId
        ) {
            return new DeviceLimitCheckResult(true, reason, policy, maxDevices, currentDeviceId, affectedDeviceId);
        }

        public static DeviceLimitCheckResult reject(
                String reason,
                String policy,
                int maxDevices,
                String currentDeviceId,
                String affectedDeviceId
        ) {
            return new DeviceLimitCheckResult(false, reason, policy, maxDevices, currentDeviceId, affectedDeviceId);
        }
    }
}
