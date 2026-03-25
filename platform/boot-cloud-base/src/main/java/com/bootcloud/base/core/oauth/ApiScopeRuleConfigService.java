package com.bootcloud.base.core.oauth;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.base.infra.mybatis.entity.SystemConfigEntity;
import com.bootcloud.base.infra.mybatis.mapper.SystemConfigMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * API Scope 动态规则配置服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>配置落库在 t_system_config，允许按接口规则动态要求 scope。</li>
 *   <li>仅管理“规则快照”，具体鉴权执行在各资源服务侧完成。</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApiScopeRuleConfigService {

    public static final String CONFIG_KEY = "oauth.api_scope_rules.v1";
    private static final String CONFIG_DESCRIPTION = "API Scope 动态规则配置（method + pathPattern + requiredScopes）";
    private static final long CACHE_TTL_MILLIS = 5_000L;
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final SystemConfigMapper systemConfigMapper;
    private final ObjectMapper objectMapper;

    private volatile CachedSnapshot cachedSnapshot;

    /**
     * 查询当前配置快照。
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
     * 全量更新规则。
     */
    @Transactional(rollbackFor = Exception.class)
    public Snapshot update(List<RuleItem> rules, String defaultPolicy, String updatedBy, String remark) {
        Snapshot current = getCurrent();
        long nextVersion = Math.max(1L, current.version() + 1L);

        StoragePayload payload = new StoragePayload();
        payload.setVersion(nextVersion);
        payload.setDefaultPolicy(normalizeDefaultPolicy(defaultPolicy));
        payload.setRules(normalizeRules(rules));
        payload.setUpdatedBy(StringUtils.hasText(updatedBy) ? updatedBy.trim() : "unknown");
        payload.setUpdatedAt(Instant.now().toString());
        payload.setRemark(StringUtils.hasText(remark) ? remark.trim() : null);

        systemConfigMapper.upsertConfig(CONFIG_KEY, writePayload(payload), CONFIG_DESCRIPTION);
        cachedSnapshot = null;
        Snapshot latest = getCurrent();
        log.info("API Scope 动态规则更新成功：version={}, defaultPolicy={}, ruleCount={}, updatedBy={}",
                latest.version(), latest.defaultPolicy(), latest.rules() == null ? 0 : latest.rules().size(), latest.updatedBy());
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
            log.warn("解析 API Scope 动态规则配置失败，回退默认配置：err={}", e.getMessage());
            return new Snapshot(1L, "LEGACY", List.of(), "system", Instant.now().toString(), "配置解析失败已回退", "DB_PARSE_FALLBACK");
        }
    }

    private Snapshot initDefault() {
        StoragePayload payload = new StoragePayload();
        payload.setVersion(1L);
        payload.setDefaultPolicy("LEGACY");
        payload.setRules(List.of());
        payload.setUpdatedBy("system");
        payload.setUpdatedAt(Instant.now().toString());
        payload.setRemark("初始化默认规则（未命中时沿用内置 GET=read/write、写请求=write）");
        systemConfigMapper.upsertConfig(CONFIG_KEY, writePayload(payload), CONFIG_DESCRIPTION);
        log.info("初始化 API Scope 动态规则配置：configKey={}", CONFIG_KEY);
        return toSnapshot(payload, "DB_INIT");
    }

    private Snapshot toSnapshot(StoragePayload payload, String source) {
        long version = payload == null || payload.getVersion() == null || payload.getVersion() <= 0 ? 1L : payload.getVersion();
        String defaultPolicy = normalizeDefaultPolicy(payload == null ? null : payload.getDefaultPolicy());
        List<RuleItem> rules = payload == null || payload.getRules() == null ? List.of() : payload.getRules();
        return new Snapshot(
                version,
                defaultPolicy,
                rules,
                payload == null ? "unknown" : payload.getUpdatedBy(),
                payload == null ? null : payload.getUpdatedAt(),
                payload == null ? null : payload.getRemark(),
                source
        );
    }

    private String writePayload(StoragePayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("API Scope 动态规则配置序列化失败: " + e.getMessage(), e);
        }
    }

    private List<RuleItem> normalizeRules(List<RuleItem> rules) {
        if (rules == null || rules.isEmpty()) {
            return List.of();
        }
        List<RuleItem> out = new ArrayList<>();
        Set<String> dedup = new LinkedHashSet<>();
        int seq = 1;
        for (RuleItem raw : rules) {
            if (raw == null) {
                continue;
            }
            RuleItem item = normalizeRule(raw, seq++);
            String dedupKey = item.getMethod() + "|" + item.getPathPattern() + "|" + item.getPriority();
            if (!dedup.add(dedupKey)) {
                throw new IllegalArgumentException("规则重复：method=" + item.getMethod() + ", pathPattern=" + item.getPathPattern() + ", priority=" + item.getPriority());
            }
            out.add(item);
        }
        out.sort((a, b) -> {
            int p = Integer.compare(a.getPriority(), b.getPriority());
            if (p != 0) {
                return p;
            }
            return String.valueOf(a.getRuleId()).compareTo(String.valueOf(b.getRuleId()));
        });
        return out;
    }

    private RuleItem normalizeRule(RuleItem raw, int seq) {
        RuleItem out = new RuleItem();
        String method = normalizeMethod(raw.getMethod());
        String pathPattern = normalizePathPattern(raw.getPathPattern());

        out.setRuleId(StringUtils.hasText(raw.getRuleId()) ? raw.getRuleId().trim() : "rule-" + seq);
        out.setEnabled(toFlag(raw.getEnabled(), true));
        out.setMethod(method);
        out.setPathPattern(pathPattern);
        out.setRequiredScopes(normalizeScopes(raw.getRequiredScopes()));
        out.setMatchMode(normalizeMatchMode(raw.getMatchMode()));
        out.setPriority(raw.getPriority() == null ? 1000 : raw.getPriority());
        out.setRemark(trimOrNull(raw.getRemark()));

        if (out.getEnabled() == 1 && out.getRequiredScopes().isEmpty()) {
            throw new IllegalArgumentException("规则 requiredScopes 不能为空：ruleId=" + out.getRuleId());
        }
        if (!PATH_MATCHER.isPattern(pathPattern) && !pathPattern.startsWith("/")) {
            throw new IllegalArgumentException("pathPattern 非法：" + pathPattern);
        }
        return out;
    }

    private static String normalizeMethod(String raw) {
        String v = trimOrNull(raw);
        if (!StringUtils.hasText(v)) {
            return "*";
        }
        String upper = v.toUpperCase(Locale.ROOT);
        return switch (upper) {
            case "*", "GET", "POST", "PUT", "PATCH", "DELETE" -> upper;
            default -> throw new IllegalArgumentException("method 非法，仅支持 GET/POST/PUT/PATCH/DELETE/*");
        };
    }

    private static String normalizePathPattern(String raw) {
        String v = trimOrNull(raw);
        if (!StringUtils.hasText(v) || !v.startsWith("/")) {
            throw new IllegalArgumentException("pathPattern 必须以 / 开头");
        }
        return v;
    }

    private static List<String> normalizeScopes(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        Set<String> dedup = new LinkedHashSet<>();
        for (String item : raw) {
            String normalized = trimOrNull(item);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            String lower = normalized.toLowerCase(Locale.ROOT);
            if (dedup.add(lower)) {
                out.add(lower);
            }
        }
        return out;
    }

    private static String normalizeMatchMode(String raw) {
        String v = trimOrNull(raw);
        if (!StringUtils.hasText(v)) {
            return "ANY";
        }
        String upper = v.toUpperCase(Locale.ROOT);
        return switch (upper) {
            case "ANY", "ALL" -> upper;
            default -> throw new IllegalArgumentException("matchMode 非法，仅支持 ANY/ALL");
        };
    }

    private static String normalizeDefaultPolicy(String raw) {
        String v = trimOrNull(raw);
        if (!StringUtils.hasText(v)) {
            return "LEGACY";
        }
        String upper = v.toUpperCase(Locale.ROOT);
        return switch (upper) {
            case "LEGACY", "DENY" -> upper;
            default -> throw new IllegalArgumentException("defaultPolicy 非法，仅支持 LEGACY/DENY");
        };
    }

    private static Integer toFlag(Integer raw, boolean defaultValue) {
        if (raw == null) {
            return defaultValue ? 1 : 0;
        }
        return raw == 0 ? 0 : 1;
    }

    private static String trimOrNull(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        return raw.trim();
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
        private String defaultPolicy;
        private List<RuleItem> rules = new ArrayList<>();
        private String updatedBy;
        private String updatedAt;
        private String remark;
    }

    @Data
    public static class RuleItem {
        /**
         * 规则标识，便于前端编辑与日志追踪。
         */
        private String ruleId;
        /**
         * 1 启用 0 禁用。
         */
        private Integer enabled;
        /**
         * HTTP 方法，支持 GET/POST/PUT/PATCH/DELETE/*。
         */
        private String method;
        /**
         * Ant Path 模式，例如 /api/user/security/**。
         */
        private String pathPattern;
        /**
         * 要求的 scope 列表，例如 ["read","write"]。
         */
        private List<String> requiredScopes = new ArrayList<>();
        /**
         * scope 命中策略：ANY 任一命中，ALL 全部命中。
         */
        private String matchMode;
        /**
         * 优先级，数字越小越优先。
         */
        private Integer priority;
        /**
         * 备注。
         */
        private String remark;
    }

    public record Snapshot(
            long version,
            String defaultPolicy,
            List<RuleItem> rules,
            String updatedBy,
            String updatedAt,
            String remark,
            String source
    ) {
    }
}
