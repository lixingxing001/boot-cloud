package com.bootcloud.gateway.core.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.internal.InternalHmacAuth;
import com.bootcloud.gateway.config.GatewayProperties;
import com.bootcloud.gateway.config.SecurityPublicPathsProperties;
import com.bootcloud.gateway.config.GatewayInternalAuthProperties;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 网关运行时公共白名单读取服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>优先从 boot-cloud-base 读取后台系统设置维护的公共白名单。</li>
 *   <li>当内部接口不可用时，自动回退到 Nacos 公共配置，避免登录入口被误锁。</li>
 *   <li>本地做 5 秒短缓存，减少每个请求都回源 boot-cloud-base。</li>
 * </ul>
 */
@Slf4j
@Service
public class GatewaySecurityPublicPathsRuntimeService {

    private static final String FETCH_PATH = "/internal/admin/security-public-paths/current";
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

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final GatewayProperties gatewayProperties;
    private final GatewayInternalAuthProperties internalAuthProperties;
    private final SecurityPublicPathsProperties fallbackProperties;

    @Value("${spring.application.name:boot-cloud-gateway}")
    private String serviceName;

    private volatile CachedSnapshot cachedSnapshot;

    public GatewaySecurityPublicPathsRuntimeService(
            WebClient webClient,
            ObjectMapper objectMapper,
            GatewayProperties gatewayProperties,
            GatewayInternalAuthProperties internalAuthProperties,
            SecurityPublicPathsProperties fallbackProperties
    ) {
        this.webClient = webClient;
        this.objectMapper = objectMapper;
        this.gatewayProperties = gatewayProperties;
        this.internalAuthProperties = internalAuthProperties;
        this.fallbackProperties = fallbackProperties;
    }

    /**
     * 查询当前白名单快照。
     */
    public Mono<Snapshot> getCurrent(String scene) {
        CachedSnapshot cached = cachedSnapshot;
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAt > now) {
            if (log.isDebugEnabled()) {
                log.debug("gateway 公共白名单命中缓存：scene={}, version={}, pathCount={}, source={}",
                        scene,
                        cached.snapshot.getVersion(),
                        cached.snapshot.getPublicPaths().size(),
                        cached.snapshot.getSource());
            }
            return Mono.just(cached.snapshot);
        }

        return fetchCurrent(scene)
                .map(snapshot -> {
                    cachedSnapshot = new CachedSnapshot(snapshot, now + CACHE_TTL_MILLIS);
                    return snapshot;
                });
    }

    private Mono<Snapshot> fetchCurrent(String scene) {
        String secret = internalAuthProperties.getInternalServiceSecret();
        if (!StringUtils.hasText(secret)) {
            Snapshot fallback = fallbackSnapshot("NACOS_FALLBACK", "内部鉴权缺失，已回退 Nacos");
            log.warn("gateway 读取公共白名单失败，内部鉴权未配置，已回退 Nacos：scene={}, pathCount={}",
                    scene, fallback.getPublicPaths().size());
            return Mono.just(fallback);
        }

        String url = "http://" + gatewayProperties.getBaseServiceId() + FETCH_PATH;
        return webClient.get()
                .uri(URI.create(url))
                .headers(headers -> injectInternalHeaders(headers, FETCH_PATH, "GET"))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(String.class)
                .map(raw -> parseSnapshot(raw, scene))
                .onErrorResume(e -> {
                    Snapshot fallback = fallbackSnapshot("NACOS_FALLBACK", "读取 boot-cloud-base 失败，已回退 Nacos");
                    log.warn("gateway 读取公共白名单失败，已回退 Nacos：scene={}, msg={}", scene, e.getMessage());
                    return Mono.just(fallback);
                });
    }

    private Snapshot parseSnapshot(String raw, String scene) {
        try {
            JsonNode root = objectMapper.readTree(raw);
            boolean success = root != null && root.path("success").asBoolean(false);
            if (!success) {
                String code = root == null ? "unknown" : root.path("error").path("code").asText("unknown");
                String message = root == null ? "unknown" : root.path("error").path("message").asText("unknown");
                log.warn("gateway 读取公共白名单响应失败，已回退 Nacos：scene={}, code={}, message={}", scene, code, message);
                return fallbackSnapshot("NACOS_FALLBACK", "boot-cloud-base 响应失败，已回退 Nacos");
            }
            JsonNode data = root.path("data");
            long version = data.path("version").asLong(1L);
            List<String> publicPaths = normalizePublicPaths(readPublicPaths(data.path("publicPaths")));
            String updatedBy = data.path("updatedBy").asText("unknown");
            String updatedAt = data.path("updatedAt").asText(null);
            String remark = data.path("remark").asText(null);
            String source = data.path("source").asText("DB");
            if (log.isDebugEnabled()) {
                log.debug("gateway 读取公共白名单成功：scene={}, version={}, pathCount={}, source={}",
                        scene, version, publicPaths.size(), source);
            }
            return new Snapshot(version, publicPaths, updatedBy, updatedAt, remark, source);
        } catch (Exception e) {
            log.warn("gateway 解析公共白名单响应失败，已回退 Nacos：scene={}, msg={}", scene, e.getMessage());
            return fallbackSnapshot("DB_PARSE_FALLBACK", "响应解析失败，已回退 Nacos");
        }
    }

    private List<String> readPublicPaths(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (JsonNode item : node) {
            if (item == null || item.isNull()) {
                continue;
            }
            out.add(item.asText(""));
        }
        return out;
    }

    private Snapshot fallbackSnapshot(String source, String remark) {
        List<String> publicPaths = normalizePublicPaths(
                fallbackProperties == null ? List.of() : fallbackProperties.getPublicPaths()
        );
        return new Snapshot(1L, publicPaths, "system", Instant.now().toString(), remark, source);
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
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (dedup.add(normalized)) {
                out.add(normalized);
            }
        }
    }

    private static String normalizePath(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (!StringUtils.hasText(value) || !value.startsWith("/")) {
            return "";
        }
        return value;
    }

    private void injectInternalHeaders(HttpHeaders headers, String path, String method) {
        if (headers == null) {
            return;
        }
        String secret = internalAuthProperties.getInternalServiceSecret();
        if (!StringUtils.hasText(secret)) {
            return;
        }
        if (StringUtils.hasText(internalAuthProperties.getInternalServiceHeader())) {
            headers.set(internalAuthProperties.getInternalServiceHeader().trim(), secret.trim());
        }
        String timestamp = InternalHmacAuth.nowTimestampSeconds();
        String normalizedPath = InternalHmacAuth.normalizePath(path);
        String signature = InternalHmacAuth.sign(secret.trim(), serviceName, timestamp, method, normalizedPath);
        headers.set(InternalHmacAuth.HEADER_SERVICE_NAME, serviceName);
        headers.set(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP, timestamp);
        headers.set(InternalHmacAuth.HEADER_INTERNAL_SIGN, signature);
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
    public static class Snapshot {
        private final long version;
        private final List<String> publicPaths;
        private final String updatedBy;
        private final String updatedAt;
        private final String remark;
        private final String source;
    }
}
