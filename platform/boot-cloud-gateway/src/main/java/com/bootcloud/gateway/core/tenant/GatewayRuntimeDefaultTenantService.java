package com.bootcloud.gateway.core.tenant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.internal.InternalHmacAuth;
import com.bootcloud.gateway.config.GatewayProperties;
import com.bootcloud.gateway.config.GatewayInternalAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * 网关运行时默认租户读取服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>优先从 boot-cloud-base 读取后台维护的默认租户，确保后台切换默认租户后，网关能够及时跟上。</li>
 *   <li>Nacos 中的 {@code boot.cloud.gateway.default-tenant-id} 只保留为最后兜底，不再作为主来源。</li>
 *   <li>这里做短缓存，避免网关每次请求都回源 boot-cloud-base。</li>
 * </ul>
 */
@Slf4j
@Service
public class GatewayRuntimeDefaultTenantService {

    private static final String DEFAULT_TENANT_PATH = "/internal/admin/tenants/default";
    private static final long CACHE_TTL_MILLIS = 5_000L;

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final GatewayProperties properties;
    private final GatewayInternalAuthProperties internalAuthProperties;

    @Value("${spring.application.name:boot-cloud-gateway}")
    private String serviceName;

    @Value("${boot.cloud.gateway.runtime-default-tenant.allow-nacos-fallback:false}")
    private boolean allowNacosFallback;

    private volatile CachedTenantId cachedTenantId;

    public GatewayRuntimeDefaultTenantService(
            WebClient webClient,
            ObjectMapper objectMapper,
            GatewayProperties properties,
            GatewayInternalAuthProperties internalAuthProperties
    ) {
        this.webClient = webClient;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.internalAuthProperties = internalAuthProperties;
    }

    /**
     * 解析当前运行时默认租户。
     *
     * @param scene 触发场景，便于日志定位
     * @return 当前应使用的默认租户 ID
     */
    public Mono<Long> resolveRuntimeDefaultTenantId(String scene) {
        CachedTenantId cached = cachedTenantId;
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAt() > now) {
            if (log.isDebugEnabled()) {
                log.debug("gateway 运行时默认租户命中缓存: tenantId={}, source={}, scene={}",
                        cached.tenantId(), cached.source(), scene);
            }
            return Mono.just(cached.tenantId());
        }

        return fetchRuntimeDefaultTenantId(scene)
                .map(snapshot -> {
                    cachedTenantId = new CachedTenantId(snapshot.tenantId(), snapshot.source(), now + CACHE_TTL_MILLIS);
                    return snapshot.tenantId();
                });
    }

    private Mono<DefaultTenantSnapshot> fetchRuntimeDefaultTenantId(String scene) {
        String secret = internalAuthProperties.getInternalServiceSecret();
        if (!StringUtils.hasText(secret)) {
            if (allowNacosFallback) {
                long fallback = fallbackTenantId();
                log.warn("gateway 读取运行时默认租户失败，内部鉴权未配置，已回退 Nacos: tenantId={}, scene={}", fallback, scene);
                return Mono.just(new DefaultTenantSnapshot(fallback, "NACOS_FALLBACK"));
            }
            log.error("gateway 读取运行时默认租户失败，内部鉴权未配置且禁止 Nacos 回退: scene={}", scene);
            return Mono.error(new IllegalStateException("gateway 内部鉴权缺失，无法读取运行时默认租户"));
        }

        String url = "http://" + properties.getBaseServiceId() + DEFAULT_TENANT_PATH;
        return webClient.get()
                .uri(URI.create(url))
                .headers(headers -> injectInternalHeaders(headers, DEFAULT_TENANT_PATH, "GET"))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(String.class)
                .map(raw -> parseSnapshot(raw, scene))
                .onErrorResume(e -> {
                    if (allowNacosFallback) {
                        long fallback = fallbackTenantId();
                        log.warn("gateway 读取运行时默认租户失败，已回退 Nacos: tenantId={}, scene={}, msg={}",
                                fallback, scene, e.getMessage());
                        return Mono.just(new DefaultTenantSnapshot(fallback, "NACOS_FALLBACK"));
                    }
                    log.error("gateway 读取运行时默认租户失败且禁止 Nacos 回退: scene={}, msg={}",
                            scene, e.getMessage(), e);
                    return Mono.error(e);
                });
    }

    private DefaultTenantSnapshot parseSnapshot(String raw, String scene) {
        try {
            JsonNode root = objectMapper.readTree(raw);
            boolean success = root != null && root.path("success").asBoolean(false);
            if (!success) {
                String code = root == null ? "unknown" : root.path("error").path("code").asText("unknown");
                String message = root == null ? "unknown" : root.path("error").path("message").asText("unknown");
                if (allowNacosFallback) {
                    long fallback = fallbackTenantId();
                    log.warn("gateway 读取运行时默认租户响应失败，已回退 Nacos: tenantId={}, scene={}, code={}, message={}",
                            fallback, scene, code, message);
                    return new DefaultTenantSnapshot(fallback, "NACOS_FALLBACK");
                }
                throw new IllegalStateException("gateway 读取运行时默认租户失败: code=" + code + ", message=" + message);
            }
            JsonNode data = root.path("data");
            long tenantId = data.path("tenantId").asLong(0L);
            if (tenantId <= 0) {
                if (allowNacosFallback) {
                    long fallback = fallbackTenantId();
                    log.warn("gateway 读取运行时默认租户缺少 tenantId，已回退 Nacos: tenantId={}, scene={}",
                            fallback, scene);
                    return new DefaultTenantSnapshot(fallback, "NACOS_FALLBACK");
                }
                throw new IllegalStateException("gateway 读取运行时默认租户缺少 tenantId");
            }
            String source = data.path("source").asText("DB_RUNTIME");
            if (log.isDebugEnabled()) {
                log.debug("gateway 读取运行时默认租户成功: tenantId={}, source={}, scene={}", tenantId, source, scene);
            }
            return new DefaultTenantSnapshot(tenantId, source);
        } catch (Exception e) {
            if (allowNacosFallback) {
                long fallback = fallbackTenantId();
                log.warn("gateway 解析运行时默认租户响应失败，已回退 Nacos: tenantId={}, scene={}, msg={}",
                        fallback, scene, e.getMessage());
                return new DefaultTenantSnapshot(fallback, "NACOS_FALLBACK");
            }
            throw new IllegalStateException("gateway 解析运行时默认租户响应失败: " + e.getMessage(), e);
        }
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

    private long fallbackTenantId() {
        return properties.getDefaultTenantId() > 0 ? properties.getDefaultTenantId() : 1L;
    }

    private record CachedTenantId(long tenantId, String source, long expiresAt) {
    }

    private record DefaultTenantSnapshot(long tenantId, String source) {
    }
}
