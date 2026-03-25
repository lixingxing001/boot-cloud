package com.bootcloud.gateway.core.filter;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.core.trace.TraceIdGenerator;
import com.bootcloud.gateway.config.GatewayProperties;
import com.bootcloud.gateway.config.GatewayRiskShieldProperties;
import com.bootcloud.gateway.core.security.GatewaySecurityPublicPathsRuntimeService;
import com.bootcloud.gateway.core.risk.CidrMatcher;
import com.bootcloud.gateway.core.risk.GeoIpCountryResolver;
import com.bootcloud.gateway.core.risk.RealClientIpResolver;
import com.bootcloud.gateway.core.risk.RiskDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 网关系统级防护过滤器（GateShield）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>第一阶段提供 IP 白名单/黑名单与地区限制。</li>
 *   <li>支持 dry-run 模式，便于先观察命中日志，再切换强拦截。</li>
 *   <li>执行顺序在鉴权前，尽量提前止损恶意流量。</li>
 *   <li>支持用户端与管理端分场景策略，避免后台误封。</li>
 * </ul>
 */
@Component
public class GatewayRiskShieldFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(GatewayRiskShieldFilter.class);

    private final GatewayRiskShieldProperties riskProperties;
    private final GatewayProperties gatewayProperties;
    private final GatewaySecurityPublicPathsRuntimeService publicPathsRuntimeService;
    private final GeoIpCountryResolver geoIpCountryResolver;
    private final ErrorMessageResolver errorMessageResolver;
    private final ObjectMapper mapper;
    private final PathMatcher pathMatcher = new AntPathMatcher();
    // 说明：去重输出非法规则日志，避免热更新配置错误时日志被持续刷屏。
    private final Set<String> warnedInvalidRules = ConcurrentHashMap.newKeySet();

    public GatewayRiskShieldFilter(
            GatewayRiskShieldProperties riskProperties,
            GatewayProperties gatewayProperties,
            GatewaySecurityPublicPathsRuntimeService publicPathsRuntimeService,
            GeoIpCountryResolver geoIpCountryResolver,
            ErrorMessageResolver errorMessageResolver,
            ObjectMapper mapper
    ) {
        this.riskProperties = riskProperties;
        this.gatewayProperties = gatewayProperties;
        this.publicPathsRuntimeService = publicPathsRuntimeService;
        this.geoIpCountryResolver = geoIpCountryResolver;
        this.errorMessageResolver = errorMessageResolver;
        this.mapper = mapper.copy().setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = path(exchange);
        PolicyContext policyContext = resolvePolicyContext(path);
        GatewayRiskShieldProperties.RiskPolicy policy = policyContext.policy();

        return publicPathsRuntimeService.getCurrent("gateway_risk_filter")
                .flatMap(snapshot -> {
                    if (!policy.isEnabled()) {
                        if (log.isDebugEnabled()) {
                            log.debug("[gate-shield] 场景策略关闭，直接放行：scene={}, path={}", policyContext.scene().name(), path);
                        }
                        return chain.filter(exchange);
                    }

                    if (isIgnoredPath(path, policy)) {
                        return chain.filter(exchange);
                    }
                    if (!policy.isIncludePublicPaths() && isPublicPath(path, snapshot.getPublicPaths())) {
                        return chain.filter(exchange);
                    }

                    String traceId = resolveTraceId(exchange);
                    GatewayRiskShieldProperties.IpRules ipRules = policy.getIp();
                    String clientIp = RealClientIpResolver.resolve(
                            exchange,
                            ipRules != null && ipRules.isTrustForwardedHeaders(),
                            ipRules == null ? null : ipRules.getForwardedHeaderCandidates()
                    );
                    CountryResolveResult countryResult = resolveCountryCode(exchange, clientIp, policy);
                    String country = countryResult.country();
                    String countrySource = countryResult.source();
                    if (log.isDebugEnabled()) {
                        log.debug("[gate-shield] 国家识别：scene={}, traceId={}, path={}, ip={}, country={}, source={}",
                                policyContext.scene().name(), traceId, path, safe(clientIp), safe(country), safe(countrySource));
                    }

                    RiskDecision decision = evaluate(policy, clientIp, country);
                    GatewayRiskShieldProperties.Mode mode = resolveMode(policy);
                    if (!decision.blocked()) {
                        if (log.isDebugEnabled()) {
                            log.debug("[gate-shield] 放行：scene={}, traceId={}, path={}, ip={}, country={}, countrySource={}, mode={}",
                                    policyContext.scene().name(), traceId, path, safe(clientIp), safe(country), safe(countrySource), mode);
                        }
                        return chain.filter(exchange);
                    }

                    Map<String, Object> audit = auditPayload(exchange, traceId, clientIp, country, countrySource, decision, mode, policyContext.scene());
                    if (mode == GatewayRiskShieldProperties.Mode.DRY_RUN) {
                        log.warn("[gate-shield] 命中规则(dry-run): {}", audit);
                        return chain.filter(exchange);
                    }

                    log.info("[gate-shield] 拦截请求: {}", audit);
                    return writeForbidden(exchange, decision, traceId, clientIp, country, countrySource, mode, policyContext.scene());
                });
    }

    private PolicyContext resolvePolicyContext(String path) {
        boolean adminScene = matchAny(riskProperties.getAdminPathPatterns(), path);
        GatewayRiskShieldProperties.RiskPolicy policy = buildDefaultPolicy();
        if (adminScene && riskProperties.getAdminPolicy() != null) {
            policy = riskProperties.getAdminPolicy();
        }
        if (adminScene && riskProperties.getAdminPolicy() == null && log.isDebugEnabled()) {
            log.debug("[gate-shield] 管理端请求未配置 adminPolicy，沿用默认策略：path={}", path);
        }
        return new PolicyContext(adminScene ? RiskScene.ADMIN : RiskScene.USER, policy);
    }

    private GatewayRiskShieldProperties.RiskPolicy buildDefaultPolicy() {
        GatewayRiskShieldProperties.RiskPolicy policy = new GatewayRiskShieldProperties.RiskPolicy();
        policy.setEnabled(riskProperties.isEnabled());
        policy.setMode(riskProperties.getMode());
        policy.setIncludePublicPaths(riskProperties.isIncludePublicPaths());
        policy.setIgnorePaths(riskProperties.getIgnorePaths());
        policy.setIp(riskProperties.getIp());
        policy.setGeo(riskProperties.getGeo());
        return policy;
    }

    private RiskDecision evaluate(GatewayRiskShieldProperties.RiskPolicy policy, String clientIp, String country) {
        RiskDecision ipDecision = evaluateIp(policy, clientIp);
        if (ipDecision.blocked()) {
            return ipDecision;
        }
        return evaluateGeo(policy, country);
    }

    private RiskDecision evaluateIp(GatewayRiskShieldProperties.RiskPolicy policy, String clientIp) {
        GatewayRiskShieldProperties.IpRules ipRules = policy == null ? null : policy.getIp();
        if (ipRules == null || !ipRules.isEnabled()) {
            return RiskDecision.allow();
        }

        List<CidrMatcher.CidrBlock> allowBlocks = CidrMatcher.parseRules(ipRules.getAllowList(), rule -> warnInvalidRule("ip-allow", rule));
        List<CidrMatcher.CidrBlock> denyBlocks = CidrMatcher.parseRules(ipRules.getDenyList(), rule -> warnInvalidRule("ip-deny", rule));
        boolean inAllowList = CidrMatcher.matchesAny(clientIp, allowBlocks);
        boolean inDenyList = CidrMatcher.matchesAny(clientIp, denyBlocks);

        // 说明：IP 白名单优先，白名单非空时只允许命中白名单的来源。
        if (!allowBlocks.isEmpty()) {
            if (inAllowList) {
                return RiskDecision.allow();
            }
            return RiskDecision.block(
                    CommonErrorCode.IP_BLOCKED.code(),
                    "客户端 IP 不在访问白名单",
                    "ip_allow_list",
                    safe(clientIp)
            );
        }
        if (inDenyList) {
            return RiskDecision.block(
                    CommonErrorCode.IP_BLOCKED.code(),
                    "客户端 IP 已被加入黑名单",
                    "ip_deny_list",
                    safe(clientIp)
            );
        }
        return RiskDecision.allow();
    }

    private RiskDecision evaluateGeo(GatewayRiskShieldProperties.RiskPolicy policy, String countryCode) {
        GatewayRiskShieldProperties.GeoRules geoRules = policy == null ? null : policy.getGeo();
        if (geoRules == null || !geoRules.isEnabled()) {
            return RiskDecision.allow();
        }

        String country = normalizeCountry(countryCode);
        List<String> allowCountries = normalizeCountries(geoRules.getAllowCountries());
        List<String> denyCountries = normalizeCountries(geoRules.getDenyCountries());

        // 说明：地区白名单优先；若白名单配置了且未命中，则直接拦截。
        if (!allowCountries.isEmpty()) {
            if (StringUtils.hasText(country) && allowCountries.contains(country)) {
                return RiskDecision.allow();
            }
            if (!StringUtils.hasText(country) && geoRules.getUnknownCountryPolicy() == GatewayRiskShieldProperties.UnknownCountryPolicy.ALLOW) {
                return RiskDecision.allow();
            }
            return RiskDecision.block(
                    CommonErrorCode.GEO_BLOCKED.code(),
                    StringUtils.hasText(country) ? "当前地区不在访问白名单" : "无法识别地区且策略为拒绝",
                    "geo_allow_list",
                    safe(country)
            );
        }

        if (StringUtils.hasText(country) && denyCountries.contains(country)) {
            return RiskDecision.block(
                    CommonErrorCode.GEO_BLOCKED.code(),
                    "当前地区已被限制访问",
                    "geo_deny_list",
                    country
            );
        }

        if (!StringUtils.hasText(country)
                && geoRules.getUnknownCountryPolicy() == GatewayRiskShieldProperties.UnknownCountryPolicy.BLOCK
                && !denyCountries.isEmpty()) {
            return RiskDecision.block(
                    CommonErrorCode.GEO_BLOCKED.code(),
                    "无法识别地区且策略为拒绝",
                    "geo_unknown_policy",
                    "UNKNOWN"
            );
        }

        return RiskDecision.allow();
    }

    /**
     * 国家码解析策略：
     * 1) 可选信任上游国家码头；
     * 2) 头缺失时尝试 GeoIP 本地库；
     * 3) GeoIP 未命中时回退到 CIDR 映射。
     */
    private CountryResolveResult resolveCountryCode(
            ServerWebExchange exchange,
            String clientIp,
            GatewayRiskShieldProperties.RiskPolicy policy
    ) {
        GatewayRiskShieldProperties.GeoRules geoRules = policy == null ? null : policy.getGeo();
        if (geoRules == null || !geoRules.isEnabled()) {
            return CountryResolveResult.empty("geo_disabled");
        }

        if (geoRules.isTrustCountryHeader() && StringUtils.hasText(geoRules.getCountryHeaderName())) {
            String raw = exchange.getRequest().getHeaders().getFirst(geoRules.getCountryHeaderName().trim());
            String code = normalizeCountry(raw);
            if (StringUtils.hasText(code)) {
                return new CountryResolveResult(code, "header:" + geoRules.getCountryHeaderName().trim());
            }
        }

        GatewayRiskShieldProperties.GeoIp geoIp = geoRules.getGeoIp();
        if (geoIp != null && geoIp.isEnabled()) {
            String resolvedByGeoIp = geoIpCountryResolver.resolveCountry(clientIp, geoIp.getMmdbPath());
            if (StringUtils.hasText(resolvedByGeoIp)) {
                return new CountryResolveResult(resolvedByGeoIp, "geoip:mmdb");
            }
        }

        Map<String, List<String>> cidrCountryMap = geoRules.getCidrCountryMap();
        if (!StringUtils.hasText(clientIp) || cidrCountryMap == null || cidrCountryMap.isEmpty()) {
            return CountryResolveResult.empty("unknown");
        }
        for (Map.Entry<String, List<String>> entry : cidrCountryMap.entrySet()) {
            String country = normalizeCountry(entry.getKey());
            if (!StringUtils.hasText(country)) {
                continue;
            }
            List<CidrMatcher.CidrBlock> blocks = CidrMatcher.parseRules(
                    entry.getValue(),
                    rule -> warnInvalidRule("geo-cidr-" + country, rule)
            );
            if (CidrMatcher.matchesAny(clientIp, blocks)) {
                return new CountryResolveResult(country, "cidr_map");
            }
        }
        return CountryResolveResult.empty("unknown");
    }

    private boolean isIgnoredPath(String path, GatewayRiskShieldProperties.RiskPolicy policy) {
        return matchAny(policy == null ? null : policy.getIgnorePaths(), path);
    }

    private boolean isPublicPath(String path, List<String> securityPublicPaths) {
        return matchAny(gatewayProperties.getPublicPaths(), path)
                || matchAny(securityPublicPaths, path);
    }

    private boolean matchAny(List<String> patterns, String path) {
        if (patterns == null || patterns.isEmpty() || !StringUtils.hasText(path)) {
            return false;
        }
        for (String pattern : patterns) {
            if (StringUtils.hasText(pattern) && pathMatcher.match(pattern.trim(), path)) {
                return true;
            }
        }
        return false;
    }

    private GatewayRiskShieldProperties.Mode resolveMode(GatewayRiskShieldProperties.RiskPolicy policy) {
        if (policy == null || policy.getMode() == null) {
            return GatewayRiskShieldProperties.Mode.ENFORCE;
        }
        return policy.getMode();
    }

    private Mono<Void> writeForbidden(
            ServerWebExchange exchange,
            RiskDecision decision,
            String traceId,
            String clientIp,
            String country,
            String countrySource,
            GatewayRiskShieldProperties.Mode mode,
            RiskScene scene
    ) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String path = path(exchange);
        String code = StringUtils.hasText(decision.code()) ? decision.code() : CommonErrorCode.FORBIDDEN.code();
        String fallbackMessage = StringUtils.hasText(decision.message()) ? decision.message() : CommonErrorCode.FORBIDDEN.defaultMessage();
        String localizedMessage = resolveLocalizedMessage(exchange, code, fallbackMessage);

        if (isApiPath(path) && !isOAuthPath(path)) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("traceId", traceId);
            details.put("ruleType", safe(decision.ruleType()));
            details.put("ruleValue", safe(decision.ruleValue()));
            details.put("clientIp", safe(clientIp));
            details.put("country", safe(country));
            details.put("countrySource", safe(countrySource));
            details.put("mode", String.valueOf(mode));
            details.put("scene", scene.name().toLowerCase(Locale.ROOT));

            ApiResponse<Void> body = ApiResponse.error(code, localizedMessage, details);
            body.setPath(path);
            try {
                byte[] bytes = mapper.writeValueAsBytes(body);
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            } catch (Exception e) {
                byte[] bytes = ("{\"success\":false,\"error\":{\"code\":\"" + safe(code)
                        + "\",\"message\":\"" + safe(localizedMessage)
                        + "\",\"details\":{\"traceId\":\"" + safe(traceId)
                        + "\"}},\"path\":\"" + safe(path) + "\"}")
                        .getBytes(StandardCharsets.UTF_8);
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            }
        }

        Map<String, String> oauthError = new LinkedHashMap<>();
        oauthError.put("error", CommonErrorCode.ACCESS_DENIED.code());
        oauthError.put("error_description", localizedMessage);
        oauthError.put("traceId", traceId);
        try {
            byte[] bytes = mapper.writeValueAsBytes(oauthError);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        } catch (Exception e) {
            byte[] bytes = ("{\"error\":\"access_denied\",\"error_description\":\"" + safe(localizedMessage)
                    + "\",\"traceId\":\"" + safe(traceId) + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        }
    }

    private Map<String, Object> auditPayload(
            ServerWebExchange exchange,
            String traceId,
            String clientIp,
            String country,
            String countrySource,
            RiskDecision decision,
            GatewayRiskShieldProperties.Mode mode,
            RiskScene scene
    ) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("traceId", traceId);
        out.put("path", path(exchange));
        out.put("method", exchange.getRequest().getMethod() == null ? "" : exchange.getRequest().getMethod().name());
        out.put("tenantId", safe(exchange.getRequest().getHeaders().getFirst(gatewayProperties.getTenantHeader())));
        out.put("clientIp", safe(clientIp));
        out.put("country", safe(country));
        out.put("countrySource", safe(countrySource));
        out.put("code", safe(decision.code()));
        out.put("ruleType", safe(decision.ruleType()));
        out.put("ruleValue", safe(decision.ruleValue()));
        out.put("mode", String.valueOf(mode));
        out.put("scene", scene.name().toLowerCase(Locale.ROOT));
        return out;
    }

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

    private String resolveLocalizedMessage(ServerWebExchange exchange, String code, String fallbackMessage) {
        if (errorMessageResolver == null || exchange == null || exchange.getRequest() == null) {
            return fallbackMessage;
        }
        String localized = errorMessageResolver.resolveByCode(exchange.getRequest(), code, fallbackMessage);
        return StringUtils.hasText(localized) ? localized : fallbackMessage;
    }

    private void warnInvalidRule(String category, String rule) {
        String key = category + "|" + rule;
        if (warnedInvalidRules.add(key)) {
            log.warn("[gate-shield] 发现非法规则，已忽略：category={}, rule={}", category, rule);
        }
    }

    private static String normalizeCountry(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String v = raw.trim().toUpperCase(Locale.ROOT);
        if (v.length() != 2) {
            return null;
        }
        return v;
    }

    private static List<String> normalizeCountries(List<String> raw) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.isEmpty()) {
            return out;
        }
        for (String item : raw) {
            String code = normalizeCountry(item);
            if (StringUtils.hasText(code)) {
                out.add(code);
            }
        }
        return out;
    }

    private static String path(ServerWebExchange exchange) {
        if (exchange == null || exchange.getRequest() == null || exchange.getRequest().getURI() == null) {
            return "";
        }
        return exchange.getRequest().getURI().getPath();
    }

    private static boolean isApiPath(String path) {
        return StringUtils.hasText(path) && path.startsWith("/api/");
    }

    private static boolean isOAuthPath(String path) {
        return StringUtils.hasText(path) && path.startsWith("/oauth/");
    }

    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\"", "'").trim();
    }

    private record CountryResolveResult(String country, String source) {
        private static CountryResolveResult empty(String source) {
            return new CountryResolveResult(null, source);
        }
    }

    private record PolicyContext(RiskScene scene, GatewayRiskShieldProperties.RiskPolicy policy) {
    }

    private enum RiskScene {
        USER,
        ADMIN
    }

    @Override
    public int getOrder() {
        // 说明：在鉴权前执行 GateShield，尽量提前过滤风险流量。
        return -110;
    }
}
