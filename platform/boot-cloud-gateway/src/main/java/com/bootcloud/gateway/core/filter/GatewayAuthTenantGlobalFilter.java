package com.bootcloud.gateway.core.filter;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.starter.client.reactive.AuthReactiveIntrospectClient;
import com.bootcloud.auth.starter.cache.IntrospectionLocalCache;
import com.bootcloud.auth.starter.dto.IntrospectResponse;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.core.trace.TraceIdGenerator;
import com.bootcloud.gateway.config.GatewayProperties;
import com.bootcloud.gateway.config.GatewayInternalAuthProperties;
import com.bootcloud.gateway.core.security.GatewaySecurityPublicPathsRuntimeService;
import com.bootcloud.gateway.core.tenant.TenantResolveCache;
import com.bootcloud.gateway.core.tenant.TenantResolveResponse;
import com.bootcloud.gateway.core.tenant.GatewayRuntimeDefaultTenantService;
import com.bootcloud.gateway.core.tenant.TenantResolverClient;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 网关全局过滤器：租户解析 + token 鉴权 + 下游透传用户信息。
 *
 * <p>说明：这是脚手架的核心入口规范。</p>
 * <ul>
 *   <li>租户解析：默认按 Host 调用 boot-cloud-base 解析并注入 X-Tenant-Id，不信任客户端租户头。</li>
 *   <li>鉴权：非 publicPaths 的请求必须携带 Bearer token，网关调用 boot-cloud-auth /oauth/check_token 校验。</li>
 *   <li>透传：注入 X-User-Id / X-Client-Id / X-Scope，便于 Java/Go 服务统一读取。</li>
 * </ul>
 */
@Component
public class GatewayAuthTenantGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(GatewayAuthTenantGlobalFilter.class);

    private final GatewayProperties properties;
    private final GatewayInternalAuthProperties internalAuthProperties;
    private final TenantResolverClient tenantResolverClient;
    private final TenantResolveCache tenantCache;
    private final GatewayRuntimeDefaultTenantService runtimeDefaultTenantService;
    private final GatewaySecurityPublicPathsRuntimeService publicPathsRuntimeService;
    private final AdminTenantRoutingPolicy adminTenantRoutingPolicy;
    private final AuthReactiveIntrospectClient authIntrospectClient;
    private final ErrorMessageResolver errorMessageResolver;
    private final ObjectMapper mapper;
    private final IntrospectionLocalCache<IntrospectResponse> introspectionCache;
    private final Counter introspectionCacheHitCounter;
    private final Counter introspectionCacheMissCounter;
    private final Counter introspectionCachePutCounter;
    private final Counter introspectionCacheEvictCounter;
    private final PathMatcher pathMatcher = new AntPathMatcher();

    public GatewayAuthTenantGlobalFilter(
            GatewayProperties properties,
            GatewayInternalAuthProperties internalAuthProperties,
            TenantResolverClient tenantResolverClient,
            TenantResolveCache tenantCache,
            GatewayRuntimeDefaultTenantService runtimeDefaultTenantService,
            GatewaySecurityPublicPathsRuntimeService publicPathsRuntimeService,
            AdminTenantRoutingPolicy adminTenantRoutingPolicy,
            AuthReactiveIntrospectClient authIntrospectClient,
            ErrorMessageResolver errorMessageResolver,
            ObjectMapper mapper,
            MeterRegistry meterRegistry
    ) {
        this.properties = properties;
        this.internalAuthProperties = internalAuthProperties;
        this.tenantResolverClient = tenantResolverClient;
        this.tenantCache = tenantCache;
        this.runtimeDefaultTenantService = runtimeDefaultTenantService;
        this.publicPathsRuntimeService = publicPathsRuntimeService;
        this.adminTenantRoutingPolicy = adminTenantRoutingPolicy;
        this.authIntrospectClient = authIntrospectClient;
        this.errorMessageResolver = errorMessageResolver;
        this.mapper = mapper.copy().setSerializationInclusion(JsonInclude.Include.NON_NULL);
        this.introspectionCacheHitCounter = Counter.builder("boot.cloud.gateway.introspection.cache.operations")
                .description("网关 introspection 本地缓存操作计数")
                .tag("operation", "hit")
                .register(meterRegistry);
        this.introspectionCacheMissCounter = Counter.builder("boot.cloud.gateway.introspection.cache.operations")
                .description("网关 introspection 本地缓存操作计数")
                .tag("operation", "miss")
                .register(meterRegistry);
        this.introspectionCachePutCounter = Counter.builder("boot.cloud.gateway.introspection.cache.operations")
                .description("网关 introspection 本地缓存操作计数")
                .tag("operation", "put")
                .register(meterRegistry);
        this.introspectionCacheEvictCounter = Counter.builder("boot.cloud.gateway.introspection.cache.operations")
                .description("网关 introspection 本地缓存操作计数")
                .tag("operation", "evict")
                .register(meterRegistry);
        this.introspectionCache = new IntrospectionLocalCache<>(
                "boot-cloud-gateway",
                log,
                properties::isIntrospectionCacheEnabled,
                () -> {
                    java.time.Duration ttl = properties.getIntrospectionCacheTtl();
                    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
                        return 15L;
                    }
                    return ttl.getSeconds();
                },
                () -> properties.getIntrospectionCacheMaxEntries() > 0 ? properties.getIntrospectionCacheMaxEntries() : 10000,
                resp -> resp != null && resp.isActive(),
                resp -> resp == null ? 0L : resp.getExp(),
                introspectionCacheHitCounter::increment,
                introspectionCacheMissCounter::increment,
                introspectionCachePutCounter::increment,
                removed -> introspectionCacheEvictCounter.increment((double) removed)
        );
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        return publicPathsRuntimeService.getCurrent("gateway_auth_filter")
                .flatMap(snapshot -> {
                    boolean isPublic = isPublicPath(path, snapshot.getPublicPaths());

                    // 1) 解析 tenantId（并注入 header）
                    return resolveTenant(exchange)
                            .flatMap(tenantId -> {
                                // public 请求也注入 tenant header，方便后续链路统一
                                ServerWebExchange withTenant = mutateHeader(exchange, properties.getTenantHeader(), String.valueOf(tenantId));
                                if (isPublic) {
                                    return chain.filter(withTenant);
                                }

                                // 2) 鉴权（Bearer token + check_token）
                                String token = resolveBearerToken(withTenant.getRequest().getHeaders());
                                if (!StringUtils.hasText(token)) {
                                    return writeError(withTenant, HttpStatus.UNAUTHORIZED, "unauthorized", "missing bearer token");
                                }

                                IntrospectResponse cached = introspectionCache.get(String.valueOf(tenantId), token);
                                if (cached != null) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("gateway introspection cache hit: tenantId={}, path={}", tenantId, path);
                                    }
                                    return handleAuthResult(withTenant, chain, cached);
                                }

                                return authIntrospectClient.introspectWithStatus(String.valueOf(tenantId), token)
                                        .flatMap(callResult -> {
                                            // 说明：
                                            // 发布窗口或网络抖动下，boot-cloud-auth 可能短时不可用。
                                            // 这里把“自省上游不可用”显式返回 503，避免前端误判成 token 失效并清空本地登录态。
                                            if (callResult == null || !callResult.upstreamAvailable()) {
                                                Integer upstreamStatus = callResult == null ? null : callResult.upstreamStatus();
                                                String msg = callResult == null ? "introspect result is null" : callResult.message();
                                                log.warn("gateway introspection unavailable: tenantId={}, path={}, upstreamStatus={}, tokenLen={}, msg={}",
                                                        tenantId,
                                                        path,
                                                        upstreamStatus,
                                                        token == null ? 0 : token.length(),
                                                        msg);
                                                return writeError(
                                                        withTenant,
                                                        HttpStatus.SERVICE_UNAVAILABLE,
                                                        CommonErrorCode.SERVICE_UNAVAILABLE.code(),
                                                        CommonErrorCode.SERVICE_UNAVAILABLE.defaultMessage()
                                                );
                                            }
                                            if (callResult.businessRejected()) {
                                                if (log.isWarnEnabled()) {
                                                    log.warn("gateway introspection rejected: tenantId={}, path={}, upstreamStatus={}, oauthError={}, oauthDescription={}",
                                                            tenantId,
                                                            path,
                                                            callResult.upstreamStatus(),
                                                            callResult.oauthError(),
                                                            callResult.oauthDescription());
                                                }
                                                return writeBusinessRejectError(withTenant, callResult);
                                            }
                                            IntrospectResponse resp = callResult.response();
                                            introspectionCache.put(String.valueOf(tenantId), token, resp);
                                            return handleAuthResult(withTenant, chain, resp);
                                        });
                            });
                });
    }

    private Mono<Long> resolveTenant(ServerWebExchange exchange) {
        String path = exchange.getRequest().getURI().getPath();
        String tenantHeader = properties.getTenantHeader();
        HttpHeaders headers = exchange.getRequest().getHeaders();
        AdminTenantRoutingPolicy.Decision adminDecision = adminTenantRoutingPolicy.decide(path, headers);
        Long adminViewTenantId = adminDecision.adminViewTenantId();
        if (adminViewTenantId != null) {
            if (log.isDebugEnabled()) {
                log.debug("tenant 解析：后台工作站点优先生效，path={}, adminViewTenantId={}, transportTenantHeader={}, acceptTenantHeaderFromClient={}, adminAuthPath={}, adminSystemView={}",
                        path,
                        adminViewTenantId,
                        headers.getFirst(tenantHeader),
                        properties.isAcceptTenantHeaderFromClient(),
                        adminDecision.adminAuthPath(),
                        adminDecision.adminSystemView());
            }
            return Mono.just(adminViewTenantId);
        }
        if (adminDecision.adminTenantView() && adminDecision.adminPath()) {
            log.warn("tenant 解析：后台租户视角请求缺少或非法的工作站点租户头，path={}, header={}",
                    path, AdminTenantRoutingPolicy.ADMIN_VIEW_TENANT_HEADER);
        }

        String explicit = headers.getFirst(tenantHeader);
        if (StringUtils.hasText(explicit)) {
            if (properties.isAcceptTenantHeaderFromClient()) {
                try {
                    long tenantId = Long.parseLong(explicit.trim());
                    if (adminDecision.adminAuthPath() && log.isDebugEnabled()) {
                        log.debug("tenant 解析：后台认证接口保留显式租户头，path={}, headerTenantId={}", path, tenantId);
                    }
                    if (adminDecision.adminSystemView() && log.isDebugEnabled()) {
                        log.debug("tenant 解析：后台 system 视角接口保留显式租户头，path={}, headerTenantId={}", path, tenantId);
                    }
                    if (adminDecision.forceRuntimeTenant()) {
                        return runtimeDefaultTenantService.resolveRuntimeDefaultTenantId("trusted_header_admin_guard")
                                .map(runtimeTenantId -> {
                                    if (runtimeTenantId != tenantId) {
                                        log.warn("tenant 解析：后台路径收到旧租户头，已改用运行时默认租户，headerTenantId={}, runtimeTenantId={}, path={}",
                                                tenantId, runtimeTenantId, path);
                                        return runtimeTenantId;
                                    }
                                    if (log.isDebugEnabled()) {
                                        log.debug("tenant 解析：来源=header(应急模式)，租户头与运行时默认租户一致，{}={}，path={}",
                                                tenantHeader, tenantId, path);
                                    }
                                    return tenantId;
                                });
                    }
                    log.debug("tenant 解析：来源=header(应急模式)，{}={}，path={}, adminPath={}, adminTenantView={}",
                            tenantHeader, tenantId, path, adminDecision.adminPath(), adminDecision.adminTenantView());
                    return Mono.just(tenantId);
                } catch (NumberFormatException e) {
                    // 交给 auth/下游统一报错也可以；这里先按非法请求返回 400
                    return Mono.error(new IllegalArgumentException("invalid " + tenantHeader));
                }
            }
            log.debug("tenant 解析：忽略客户端租户头，header={}，value={}，path={}",
                    tenantHeader, explicit, path);
        }

        ResolvedHost resolvedHost = resolveHost(exchange.getRequest().getHeaders());
        String host = resolvedHost.host();
        if (log.isDebugEnabled()) {
            log.debug("tenant 解析：host 判定完成，source={}，host={}，path={}",
                    resolvedHost.source(), host, path);
        }
        if (!StringUtils.hasText(host)) {
            if (properties.isFailOnTenantResolveError()) {
                log.warn("tenant 解析失败：host 缺失且 failOnTenantResolveError=true，source={}，path={}",
                        resolvedHost.source(), path);
                return Mono.error(new IllegalStateException("missing host for tenant resolve"));
            }
            return resolveRuntimeDefaultTenant("missing_host", null, resolvedHost.source(), path);
        }

        // 说明：开发/测试环境经常使用 IP/localhost 访问网关，此时不走域名映射解析。
        // 当前这里改为优先回落“后台运行时默认租户”，确保后台切换默认租户后，网关无需同步改 Nacos 也能生效。
        if (isIpOrLocalhost(host)) {
            if (properties.isFailOnTenantResolveError()) {
                log.warn("tenant 解析失败：host 为 ip/localhost 且 failOnTenantResolveError=true，host={}，path={}", host, path);
                return Mono.error(new IllegalStateException("ip/localhost host is not allowed for tenant resolve"));
            }
            return resolveRuntimeDefaultTenant("ip_or_localhost", host, resolvedHost.source(), path);
        }

        TenantResolveResponse cached = tenantCache.get(host);
        if (cached != null && cached.getTenantId() > 0) {
            log.debug("tenant 解析：来源=cache，host={}，tenantId={}，fromDefault={}，path={}",
                    host, cached.getTenantId(), cached.isFromDefault(), path);
            return Mono.just(cached.getTenantId());
        }

        return tenantResolverClient.resolveTenantIdByDomain(host)
                .flatMap(resp -> {
                    tenantCache.put(host, resp);
                    log.debug("tenant 解析：来源=boot-cloud-base，host={}，tenantId={}，fromDefault={}，path={}",
                            host, resp.getTenantId(), resp.isFromDefault(), path);
                    if (resp.getTenantId() > 0) {
                        return Mono.just(resp.getTenantId());
                    }
                    return resolveRuntimeDefaultTenant("resolve_empty_result", host, resolvedHost.source(), path);
                })
                .onErrorResume(e -> {
                    if (properties.isFailOnTenantResolveError()) {
                        return Mono.error(e);
                    }
                    return resolveRuntimeDefaultTenant("resolve_error", host, resolvedHost.source(), path)
                            .doOnNext(tenantId -> log.warn("tenant 解析：boot-cloud-base 调用失败，已走运行时默认租户，host={}，tenantId={}，path={}，err={}",
                                    host, tenantId, path, e.getMessage()));
                });
    }

    /**
     * 统一从“后台运行时默认租户”读取 fallback 值。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>IP/localhost、Host 缺失、域名解析失败时，都优先读后台维护的默认租户。</li>
     *   <li>Nacos 中的 defaultTenantId 只作为最后兜底，避免后台切换默认租户后网关仍然使用旧值。</li>
     * </ul>
     */
    private Mono<Long> resolveRuntimeDefaultTenant(String scene, String host, String source, String path) {
        return runtimeDefaultTenantService.resolveRuntimeDefaultTenantId(scene)
                .doOnNext(tenantId -> log.warn("tenant 解析：已走运行时默认租户，scene={}, host={}, source={}, tenantId={}, path={}",
                        scene, host, source, tenantId, path));
    }

    /**
     * 判断 host 是否为“开发/测试常见的本地地址”。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>IP/localhost 访问网关时通常不具备“域名 -> tenantId”语义。</li>
     *   <li>是否回落 defaultTenantId 由 failOnTenantResolveError 控制。</li>
     *   <li>这里不做 DNS 解析，避免把域名误判成 IP（同时减少外部依赖）。</li>
     * </ul>
     */
    private static boolean isIpOrLocalhost(String host) {
        if (!StringUtils.hasText(host)) {
            return false;
        }
        String h = host.trim().toLowerCase();
        if ("localhost".equals(h) || "127.0.0.1".equals(h) || "::1".equals(h)) {
            return true;
        }

        // IPv6：简单判定（域名本身不会包含 ':'，且端口已在 resolveHost() 去除）
        if (h.contains(":")) {
            return true;
        }

        // IPv4：四段数字且每段 0~255
        String[] parts = h.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                char c = p.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
            }
            int v;
            try {
                v = Integer.parseInt(p);
            } catch (NumberFormatException e) {
                return false;
            }
            if (v < 0 || v > 255) {
                return false;
            }
        }
        return true;
    }

    private Mono<Void> handleAuthResult(ServerWebExchange exchange, GatewayFilterChain chain, IntrospectResponse resp) {
        if (resp == null || !resp.isActive()) {
            return writeError(exchange, HttpStatus.UNAUTHORIZED, "unauthorized", "invalid token");
        }

        ServerWebExchange mutated = exchange;
        if (StringUtils.hasText(resp.getUserId())) {
            mutated = mutateHeader(mutated, properties.getUserIdHeader(), resp.getUserId());
        }
        if (StringUtils.hasText(resp.getClientId())) {
            mutated = mutateHeader(mutated, properties.getClientIdHeader(), resp.getClientId());
        }
        if (StringUtils.hasText(resp.getScope())) {
            mutated = mutateHeader(mutated, properties.getScopeHeader(), resp.getScope());
        }

        return chain.filter(injectInternalAuth(mutated));
    }

    private boolean isPublicPath(String path, List<String> securityPublicPaths) {
        if (!StringUtils.hasText(path)) {
            return true;
        }
        // 说明：
        // publicPaths 分两处来源：
        // 1) boot.cloud.gateway.public-paths（网关私有）
        // 2) 系统设置公共白名单（读取 DB，异常时回退 boot.cloud.security.public-paths）
        return matchAny(properties.getPublicPaths(), path) || matchAny(securityPublicPaths, path);
    }

    private boolean matchAny(Iterable<String> patterns, String path) {
        if (patterns == null) {
            return false;
        }
        for (String pattern : patterns) {
            if (StringUtils.hasText(pattern) && pathMatcher.match(pattern.trim(), path)) {
                return true;
            }
        }
        return false;
    }

    private static String resolveBearerToken(HttpHeaders headers) {
        String v = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(v)) {
            return null;
        }
        String s = v.trim();
        if (!s.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = s.substring(7).trim();
        return StringUtils.hasText(token) ? token : null;
    }

    private ResolvedHost resolveHost(HttpHeaders headers) {
        if (headers == null) {
            return ResolvedHost.empty();
        }

        if (properties.isTrustForwardedHostHeaders()) {
            ResolvedHost forwarded = resolveHostFromForwardedHeaders(headers, properties.getForwardedHostHeaderCandidates());
            if (forwarded != null && StringUtils.hasText(forwarded.host())) {
                return forwarded;
            }
            if (log.isDebugEnabled()) {
                log.debug("tenant 解析：trustForwardedHostHeaders=true，但未命中候选头，candidates={}",
                        properties.getForwardedHostHeaderCandidates());
            }
        }

        if (headers.getHost() != null) {
            String host = headers.getHost().getHostName();
            if (StringUtils.hasText(host)) {
                return new ResolvedHost(host.trim().toLowerCase(Locale.ROOT), "Host(parsed)");
            }
        }
        String raw = headers.getFirst("Host");
        String normalized = normalizeHostCandidate(raw);
        if (!StringUtils.hasText(normalized)) {
            return ResolvedHost.empty();
        }
        return new ResolvedHost(normalized, "Host(raw)");
    }

    private static ResolvedHost resolveHostFromForwardedHeaders(HttpHeaders headers, List<String> headerCandidates) {
        if (headers == null || headerCandidates == null || headerCandidates.isEmpty()) {
            return null;
        }
        for (String headerName : headerCandidates) {
            if (!StringUtils.hasText(headerName)) {
                continue;
            }
            String raw = headers.getFirst(headerName.trim());
            if (!StringUtils.hasText(raw)) {
                continue;
            }
            String candidate;
            if ("forwarded".equalsIgnoreCase(headerName.trim())) {
                candidate = extractHostFromForwardedHeader(raw);
            } else {
                candidate = extractFirstCsvToken(raw);
            }
            String normalized = normalizeHostCandidate(candidate);
            if (StringUtils.hasText(normalized)) {
                return new ResolvedHost(normalized, headerName.trim());
            }
        }
        return null;
    }

    private static String extractHostFromForwardedHeader(String forwardedValue) {
        if (!StringUtils.hasText(forwardedValue)) {
            return null;
        }
        String firstEntry = extractFirstCsvToken(forwardedValue);
        if (!StringUtils.hasText(firstEntry)) {
            return null;
        }
        String[] parts = firstEntry.split(";");
        for (String part : parts) {
            if (!StringUtils.hasText(part)) {
                continue;
            }
            String s = part.trim();
            if (s.regionMatches(true, 0, "host=", 0, 5)) {
                return s.substring(5).trim();
            }
        }
        return null;
    }

    private static String extractFirstCsvToken(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String[] parts = value.split(",");
        if (parts.length == 0) {
            return value.trim();
        }
        return parts[0].trim();
    }

    private static String normalizeHostCandidate(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String s = raw.trim();
        if (s.startsWith("\"") && s.endsWith("\"") && s.length() >= 2) {
            s = s.substring(1, s.length() - 1).trim();
        }

        // IPv6 常见格式：[::1]:8080，这里只提取地址段
        if (s.startsWith("[") && s.contains("]")) {
            int end = s.indexOf(']');
            if (end > 1) {
                return s.substring(1, end).trim().toLowerCase(Locale.ROOT);
            }
        }

        // 仅在“单冒号”场景裁剪端口，避免误伤 IPv6 字面量
        int firstColon = s.indexOf(':');
        int lastColon = s.lastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon) {
            s = s.substring(0, firstColon);
        }
        s = s.trim().toLowerCase(Locale.ROOT);
        return StringUtils.hasText(s) ? s : null;
    }

    private static ServerWebExchange mutateHeader(ServerWebExchange exchange, String name, String value) {
        ServerHttpRequest req = exchange.getRequest().mutate()
                .headers(h -> {
                    h.remove(name);
                    h.add(name, value);
                })
                .build();
        return exchange.mutate().request(req).build();
    }

    private ServerWebExchange injectInternalAuth(ServerWebExchange exchange) {
        // 说明：兼容旧服务
        // 旧服务如果要信任 X-User-Id，需要同时验证一个“内部密钥头”；
        // 该头只应由网关注入，下游验证通过后才认为请求来自可信网关。
        if (internalAuthProperties != null
                && StringUtils.hasText(internalAuthProperties.getInternalServiceHeader())
                && StringUtils.hasText(internalAuthProperties.getInternalServiceSecret())) {
            return mutateHeader(exchange,
                    internalAuthProperties.getInternalServiceHeader(),
                    internalAuthProperties.getInternalServiceSecret());
        }
        return exchange;
    }

    private Mono<Void> writeError(ServerWebExchange exchange, HttpStatus status, String error, String description) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String path = exchange == null || exchange.getRequest() == null || exchange.getRequest().getURI() == null
                ? ""
                : exchange.getRequest().getURI().getPath();
        String lookupCode = resolveLookupCode(error, description);
        String localizedDescription = resolveLocalizedDescription(exchange, error, description);

        // 说明：
        // /api/** 统一输出 ApiResponse，保证前端按 success/error.code 固定分支。
        // /oauth/** 保持 OAuth 协议风格，避免影响标准客户端兼容。
        if (isApiPath(path) && !isOAuthPath(path)) {
            String traceId = resolveTraceId(exchange);
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("traceId", traceId);

            ApiResponse<Void> body = ApiResponse.error(lookupCode, localizedDescription, details);
            body.setPath(path);
            if (log.isDebugEnabled()) {
                log.debug("网关统一错误响应：path={}, status={}, code={}, traceId={}",
                        path, status.value(), lookupCode, traceId);
            }
            try {
                byte[] bytes = mapper.writeValueAsBytes(body);
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            } catch (Exception e) {
                byte[] bytes = ("{\"success\":false,\"error\":{\"code\":\"" + safe(lookupCode)
                        + "\",\"message\":\"" + safe(localizedDescription)
                        + "\",\"details\":{\"traceId\":\"" + safe(traceId)
                        + "\"}},\"path\":\"" + safe(path) + "\"}")
                        .getBytes(StandardCharsets.UTF_8);
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            }
        }

        GatewayErrorResponse body = new GatewayErrorResponse();
        body.error = error;
        body.errorDescription = localizedDescription;

        try {
            byte[] bytes = mapper.writeValueAsBytes(body);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        } catch (Exception e) {
            byte[] bytes = ("{\"error\":\"" + error + "\",\"error_description\":\"" + safe(localizedDescription) + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        }
    }

    /**
     * 自省 4xx 业务拒绝统一映射。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>tenant is not allowed：明确返回 403 tenant_not_allowed。</li>
     *   <li>tenant is disabled：明确返回 403 tenant_disabled。</li>
     *   <li>缺少/非法租户头：返回 400，并给出明确租户头错误码。</li>
     *   <li>invalid_client：说明网关到认证中心的 introspection client 配置错误，返回 500，避免继续伪装成 service_unavailable。</li>
     *   <li>其他 4xx 继续保留 OAuth 原始错误码和描述，便于前端与日志定位。</li>
     * </ul>
     */
    private Mono<Void> writeBusinessRejectError(ServerWebExchange exchange, AuthReactiveIntrospectClient.IntrospectCallResult callResult) {
        String oauthError = callResult == null ? "" : callResult.oauthError();
        String oauthDescription = callResult == null ? "" : callResult.oauthDescription();
        String normalizedError = oauthError == null ? "" : oauthError.trim().toLowerCase(Locale.ROOT);
        String normalizedDesc = oauthDescription == null ? "" : oauthDescription.trim().toLowerCase(Locale.ROOT);

        if ("invalid_request".equals(normalizedError) && "tenant is not allowed".equals(normalizedDesc)) {
            return writeError(exchange, HttpStatus.FORBIDDEN,
                    CommonErrorCode.TENANT_NOT_ALLOWED.code(),
                    CommonErrorCode.TENANT_NOT_ALLOWED.defaultMessage());
        }
        if ("invalid_request".equals(normalizedError) && "tenant is disabled".equals(normalizedDesc)) {
            return writeError(exchange, HttpStatus.FORBIDDEN,
                    CommonErrorCode.TENANT_DISABLED.code(),
                    CommonErrorCode.TENANT_DISABLED.defaultMessage());
        }
        if ("invalid_request".equals(normalizedError) && "missing x-tenant-id".equals(normalizedDesc)) {
            return writeError(exchange, HttpStatus.BAD_REQUEST,
                    CommonErrorCode.TENANT_HEADER_MISSING.code(),
                    CommonErrorCode.TENANT_HEADER_MISSING.defaultMessage());
        }
        if ("invalid_request".equals(normalizedError) && "invalid x-tenant-id".equals(normalizedDesc)) {
            return writeError(exchange, HttpStatus.BAD_REQUEST,
                    CommonErrorCode.TENANT_HEADER_INVALID.code(),
                    CommonErrorCode.TENANT_HEADER_INVALID.defaultMessage());
        }
        if ("invalid_client".equals(normalizedError)) {
            return writeError(exchange, HttpStatus.INTERNAL_SERVER_ERROR,
                    CommonErrorCode.INVALID_CLIENT.code(),
                    "认证服务客户端配置错误");
        }

        HttpStatus status = HttpStatus.BAD_REQUEST;
        if ("access_denied".equals(normalizedError) || "forbidden".equals(normalizedError)) {
            status = HttpStatus.FORBIDDEN;
        } else if ("invalid_client".equals(normalizedError)) {
            status = HttpStatus.UNAUTHORIZED;
        }
        String errorCode = StringUtils.hasText(oauthError) ? oauthError.trim() : CommonErrorCode.INVALID_REQUEST.code();
        String description = StringUtils.hasText(oauthDescription) ? oauthDescription.trim() : errorCode;
        return writeError(exchange, status, errorCode, description);
    }

    /**
     * 网关拦截错误文案本地化。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>保持 error 字段兼容现有前端分支。</li>
     *   <li>通过 Accept-Language 只切换 errorDescription 展示文案。</li>
     * </ul>
     */
    private String resolveLocalizedDescription(ServerWebExchange exchange, String error, String fallbackDescription) {
        if (errorMessageResolver == null || exchange == null || exchange.getRequest() == null) {
            return fallbackDescription;
        }
        String lookupCode = resolveLookupCode(error, fallbackDescription);
        String localized = errorMessageResolver.resolveByCode(exchange.getRequest(), lookupCode, fallbackDescription);
        if (log.isDebugEnabled()) {
            String path = exchange.getRequest().getURI() == null ? "" : exchange.getRequest().getURI().getPath();
            String language = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ACCEPT_LANGUAGE);
            log.debug("网关错误文案本地化：path={}, acceptLanguage={}, error={}, lookupCode={}, localized={}",
                    path, language, error, lookupCode, localized);
        }
        return StringUtils.hasText(localized) ? localized : fallbackDescription;
    }

    /**
     * 把网关内部 error + description 映射到公共错误码目录，便于命中 i18n 资源。
     */
    private static String resolveLookupCode(String error, String description) {
        if ("unauthorized".equalsIgnoreCase(error)) {
            if ("invalid token".equalsIgnoreCase(description)) {
                return CommonErrorCode.INVALID_TOKEN.code();
            }
            return CommonErrorCode.UNAUTHORIZED.code();
        }
        return error;
    }

    /**
     * 网关响应 traceId 统一来源。
     */
    private static String resolveTraceId(ServerWebExchange exchange) {
        if (exchange == null) {
            return TraceIdGenerator.generate();
        }
        Object fromAttr = exchange.getAttributes().get(TraceIdContext.REACTOR_KEY);
        if (fromAttr != null && StringUtils.hasText(String.valueOf(fromAttr))) {
            return String.valueOf(fromAttr).trim();
        }
        String fromHeader = exchange.getRequest() == null
                ? null
                : exchange.getRequest().getHeaders().getFirst("X-Trace-Id");
        if (StringUtils.hasText(fromHeader)) {
            return fromHeader.trim();
        }
        return TraceIdGenerator.generate();
    }

    private static boolean isApiPath(String path) {
        return StringUtils.hasText(path) && path.startsWith("/api/");
    }

    private static boolean isOAuthPath(String path) {
        return StringUtils.hasText(path) && path.startsWith("/oauth/");
    }

    private static String safe(String s) {
        if (s == null) return "";
        return s.replace("\"", "'");
    }

    @Override
    public int getOrder() {
        // 尽量靠前：先注入 tenant + 鉴权，再进入路由与其他过滤器
        return -100;
    }

    private static class ResolvedHost {
        private final String host;
        private final String source;

        private ResolvedHost(String host, String source) {
            this.host = host;
            this.source = source;
        }

        private static ResolvedHost empty() {
            return new ResolvedHost(null, "none");
        }

        private String host() {
            return host;
        }

        private String source() {
            return source;
        }
    }

    private static class GatewayErrorResponse {
        public String error;
        public String errorDescription;
    }
}
