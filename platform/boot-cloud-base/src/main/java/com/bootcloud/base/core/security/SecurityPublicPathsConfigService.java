package com.bootcloud.base.core.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.base.infra.mybatis.entity.SystemConfigEntity;
import com.bootcloud.base.infra.mybatis.mapper.SystemConfigMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 公共白名单路径配置服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>配置统一写入 {@code t_system_config}，作为网关与资源服务的运行时白名单来源。</li>
 *   <li>保留 Nacos 作为初始化与故障兜底来源，降低迁移窗口的锁死风险。</li>
 *   <li>会自动补齐登录与启动链路必需的核心白名单，避免误操作把系统入口锁住。</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityPublicPathsConfigService {

    public static final String CONFIG_KEY = "security.public_paths.v1";
    private static final String CONFIG_DESCRIPTION = "公共白名单路径配置（网关+资源服务共享）";
    private static final long CACHE_TTL_MILLIS = 5_000L;
    private static final List<String> REQUIRED_PUBLIC_PATHS = List.of(
            "/oauth/**",
            "/api/auth/**",
            "/api/web/auth/**",
            "/api/web/admin/auth/**",
            "/api/config",
            "/api/admin/config",
            "/api/web/admin/runtime/default-tenant",
            "/api/web/admin/runtime/login-tenants",
            "/api/web/admin/runtime/version-meta",
            "/api/web/runtime/default-tenant",
            "/api/web/runtime/version-meta"
    );

    private final SystemConfigMapper systemConfigMapper;
    private final ObjectMapper objectMapper;
    private final Environment environment;

    private volatile CachedSnapshot cachedSnapshot;

    /**
     * 查询当前白名单快照。
     */
    public Snapshot getCurrent() {
        CachedSnapshot cached = cachedSnapshot;
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAt > now) {
            return cached.snapshot;
        }
        synchronized (this) {
            cached = cachedSnapshot;
            if (cached != null && cached.expiresAt > now) {
                return cached.snapshot;
            }
            Snapshot loaded = loadSnapshot();
            cachedSnapshot = new CachedSnapshot(loaded, now + CACHE_TTL_MILLIS);
            return loaded;
        }
    }

    /**
     * 全量更新公共白名单。
     */
    @Transactional(rollbackFor = Exception.class)
    public Snapshot update(List<String> publicPaths, String updatedBy, String remark) {
        Snapshot current = getCurrent();
        long nextVersion = Math.max(1L, current.version() + 1L);

        StoragePayload payload = new StoragePayload();
        payload.setVersion(nextVersion);
        payload.setPublicPaths(normalizePublicPaths(publicPaths));
        payload.setUpdatedBy(StringUtils.hasText(updatedBy) ? updatedBy.trim() : "unknown");
        payload.setUpdatedAt(Instant.now().toString());
        payload.setRemark(StringUtils.hasText(remark) ? remark.trim() : null);

        systemConfigMapper.upsertConfig(CONFIG_KEY, writePayload(payload), CONFIG_DESCRIPTION);
        cachedSnapshot = null;
        Snapshot latest = getCurrent();
        log.info("公共白名单更新成功：version={}, pathCount={}, updatedBy={}",
                latest.version(),
                latest.publicPaths() == null ? 0 : latest.publicPaths().size(),
                latest.updatedBy());
        return latest;
    }

    private Snapshot loadSnapshot() {
        SystemConfigEntity entity = systemConfigMapper.selectOne(new LambdaQueryWrapper<SystemConfigEntity>()
                .eq(SystemConfigEntity::getConfigKey, CONFIG_KEY)
                .last("LIMIT 1"));
        if (entity == null || !StringUtils.hasText(entity.getConfigValue())) {
            return initDefault();
        }
        try {
            StoragePayload payload = objectMapper.readValue(entity.getConfigValue(), StoragePayload.class);
            return toSnapshot(payload, "DB");
        } catch (Exception e) {
            log.warn("解析公共白名单配置失败，回退 Nacos 初始化配置：err={}", e.getMessage());
            return fallbackSnapshot("DB_PARSE_FALLBACK", "配置解析失败，已回退 Nacos 初始化值");
        }
    }

    private Snapshot initDefault() {
        StoragePayload payload = new StoragePayload();
        payload.setVersion(1L);
        payload.setPublicPaths(normalizePublicPaths(loadBootstrapPublicPaths()));
        payload.setUpdatedBy("system");
        payload.setUpdatedAt(Instant.now().toString());
        payload.setRemark("初始化默认公共白名单（来源：Nacos + 系统核心路径）");
        systemConfigMapper.upsertConfig(CONFIG_KEY, writePayload(payload), CONFIG_DESCRIPTION);
        log.info("初始化公共白名单配置：configKey={}, pathCount={}", CONFIG_KEY, payload.getPublicPaths().size());
        return toSnapshot(payload, "DB_INIT");
    }

    private Snapshot fallbackSnapshot(String source, String remark) {
        return new Snapshot(
                1L,
                normalizePublicPaths(loadBootstrapPublicPaths()),
                "system",
                Instant.now().toString(),
                remark,
                source
        );
    }

    private Snapshot toSnapshot(StoragePayload payload, String source) {
        long version = payload == null || payload.getVersion() == null || payload.getVersion() <= 0 ? 1L : payload.getVersion();
        List<String> publicPaths = payload == null ? List.of() : normalizePublicPaths(payload.getPublicPaths());
        return new Snapshot(
                version,
                publicPaths,
                payload == null ? "unknown" : payload.getUpdatedBy(),
                payload == null ? null : payload.getUpdatedAt(),
                payload == null ? null : payload.getRemark(),
                source
        );
    }

    private List<String> loadBootstrapPublicPaths() {
        List<String> configured = Binder.get(environment)
                .bind("boot.cloud.security.public-paths", Bindable.listOf(String.class))
                .orElse(List.of());
        return configured == null ? List.of() : configured;
    }

    private String writePayload(StoragePayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("公共白名单配置序列化失败: " + e.getMessage(), e);
        }
    }

    private List<String> normalizePublicPaths(List<String> publicPaths) {
        Set<String> dedup = new LinkedHashSet<>();
        List<String> out = new ArrayList<>();

        appendPaths(out, dedup, publicPaths);
        appendPaths(out, dedup, REQUIRED_PUBLIC_PATHS);
        return out;
    }

    private void appendPaths(List<String> out, Set<String> dedup, List<String> rawPaths) {
        if (rawPaths == null || rawPaths.isEmpty()) {
            return;
        }
        for (String raw : rawPaths) {
            String normalized = normalizePath(raw);
            if (dedup.add(normalized)) {
                out.add(normalized);
            }
        }
    }

    private static String normalizePath(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("白名单路径不能为空");
        }
        if (!value.startsWith("/")) {
            throw new IllegalArgumentException("白名单路径必须以 / 开头: " + value);
        }
        return value;
    }

    private static class CachedSnapshot {
        private final Snapshot snapshot;
        private final long expiresAt;

        private CachedSnapshot(Snapshot snapshot, long expiresAt) {
            this.snapshot = snapshot;
            this.expiresAt = expiresAt;
        }
    }

    @Data
    private static class StoragePayload {
        private Long version;
        private List<String> publicPaths = new ArrayList<>();
        private String updatedBy;
        private String updatedAt;
        private String remark;
    }

    public record Snapshot(
            long version,
            List<String> publicPaths,
            String updatedBy,
            String updatedAt,
            String remark,
            String source
    ) {
    }
}
