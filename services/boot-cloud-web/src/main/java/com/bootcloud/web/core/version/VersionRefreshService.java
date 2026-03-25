package com.bootcloud.web.core.version;

import com.bootcloud.web.config.ClientVersionProperties;
import com.bootcloud.web.core.util.LogSafeUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * 版本刷新策略服务。
 *
 * <ul>
 *   <li>统一管理 public/admin 两类前端的版本提示元数据。</li>
 *   <li>提供“客户端版本是否允许继续请求”的判定逻辑，给拦截器复用。</li>
 * </ul>
 */
@Slf4j
@Service
public class VersionRefreshService {

    public static final String APP_PRIMARY = "public";
    public static final String APP_ADMIN = "admin";

    private final ClientVersionProperties properties;

    public VersionRefreshService(ClientVersionProperties properties) {
        this.properties = properties;
    }

    public VersionMetaView buildVersionMeta(String app, String currentBuildId) {
        ResolvedPolicy resolved = resolvePolicy(app);
        String normalizedCurrentBuild = normalize(currentBuildId);
        boolean hasUpdate = StringUtils.hasText(resolved.policy.currentBuildId())
                && !resolved.policy.currentBuildId().equals(normalizedCurrentBuild);
        if (log.isDebugEnabled()) {
            log.debug("版本元数据查询：app={}, clientBuildId={}, serverBuildId={}, hasUpdate={}, policy={}",
                    resolved.app,
                    LogSafeUtil.sanitizeAndTruncate(normalizedCurrentBuild, 96),
                    resolved.policy.currentBuildId(),
                    hasUpdate,
                    resolved.policy.refreshPolicy());
        }
        return new VersionMetaView(
                resolved.app,
                resolved.policy.currentBuildId(),
                resolved.policy.refreshPolicy(),
                resolved.policy.message(),
                resolved.policy.graceSeconds(),
                hasUpdate,
                System.currentTimeMillis()
        );
    }

    public boolean shouldEnforceVersion(String app) {
        if (!properties.isEnabled()) {
            return false;
        }
        return resolvePolicy(app).policy.enforceOnMismatch();
    }

    public boolean isBuildAllowed(String app, String clientBuildId) {
        ResolvedPolicy resolved = resolvePolicy(app);
        String normalizedClientBuild = normalize(clientBuildId);
        if (!StringUtils.hasText(normalizedClientBuild)) {
            return false;
        }
        Set<String> accepted = resolved.policy.acceptedBuildIds();
        return accepted.contains(normalizedClientBuild);
    }

    public VersionPolicySnapshot snapshot(String app) {
        return resolvePolicy(app).policy;
    }

    public String resolveAppByPathOrHeader(String path, String appHeader) {
        String normalizedHeader = normalizeApp(appHeader);
        if (StringUtils.hasText(normalizedHeader)) {
            return normalizedHeader;
        }
        String normalizedPath = StringUtils.hasText(path) ? path.trim() : "";
        if (normalizedPath.startsWith("/api/web/admin/") || normalizedPath.startsWith("/api/admin/")) {
            return APP_ADMIN;
        }
        return APP_PRIMARY;
    }

    private ResolvedPolicy resolvePolicy(String app) {
        String normalizedApp = normalizeApp(app);
        if (APP_ADMIN.equals(normalizedApp)) {
            return new ResolvedPolicy(APP_ADMIN, toSnapshot(properties.getAdmin()));
        }
        return new ResolvedPolicy(APP_PRIMARY, toSnapshot(properties.getPrimary()));
    }

    private VersionPolicySnapshot toSnapshot(ClientVersionProperties.ClientVersionPolicy source) {
        ClientVersionProperties.ClientVersionPolicy safe = source == null
                ? new ClientVersionProperties.ClientVersionPolicy()
                : source;

        String currentBuildId = normalize(safe.getCurrentBuildId());
        if (!StringUtils.hasText(currentBuildId)) {
            currentBuildId = "dev-local";
        }
        String refreshPolicy = normalizePolicy(safe.getRefreshPolicy());
        String message = StringUtils.hasText(safe.getMessage())
                ? safe.getMessage().trim()
                : "检测到新版本，请刷新页面后继续操作";
        long graceSeconds = Math.max(0, safe.getGraceSeconds());
        boolean enforceOnMismatch = safe.isEnforceOnMismatch();

        Set<String> acceptedBuildIds = new LinkedHashSet<>();
        if (safe.getAcceptedBuildIds() != null) {
            safe.getAcceptedBuildIds().forEach(item -> {
                String normalized = normalize(item);
                if (StringUtils.hasText(normalized)) {
                    acceptedBuildIds.add(normalized);
                }
            });
        }
        if (acceptedBuildIds.isEmpty()) {
            acceptedBuildIds.add(normalize(currentBuildId));
        }

        return new VersionPolicySnapshot(
                currentBuildId,
                refreshPolicy,
                message,
                graceSeconds,
                enforceOnMismatch,
                acceptedBuildIds
        );
    }

    private String normalizeApp(String value) {
        String normalized = normalize(value);
        if (APP_ADMIN.equals(normalized)) {
            return APP_ADMIN;
        }
        return APP_PRIMARY;
    }

    private String normalizePolicy(String value) {
        String normalized = normalize(value);
        if ("none".equals(normalized) || "force".equals(normalized)) {
            return normalized;
        }
        return "soft";
    }

    private String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private record ResolvedPolicy(String app, VersionPolicySnapshot policy) {
    }

    /**
     * 返回给前端的版本元数据。
     */
    public record VersionMetaView(
            String app,
            String serverBuildId,
            String refreshPolicy,
            String message,
            long graceSeconds,
            boolean hasUpdate,
            long serverTimeMs
    ) {
    }

    /**
     * 后端策略快照。
     */
    public record VersionPolicySnapshot(
            String currentBuildId,
            String refreshPolicy,
            String message,
            long graceSeconds,
            boolean enforceOnMismatch,
            Set<String> acceptedBuildIds
    ) {
    }
}
