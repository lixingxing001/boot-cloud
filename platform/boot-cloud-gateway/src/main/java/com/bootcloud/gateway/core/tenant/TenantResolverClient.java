package com.bootcloud.gateway.core.tenant;

import com.bootcloud.gateway.config.GatewayProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

/**
 * 网关调用 boot-cloud-base：按域名解析 tenantId。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>优先按域名映射解析 tenantId，保持网关和 boot-cloud-base 的租户语义一致。</li>
 *   <li>当域名缺失或解析失败时，回退到后台维护的运行时默认租户，Nacos 只保留最后兜底。</li>
 * </ul>
 */
@Component
public class TenantResolverClient {

    private static final Logger log = LoggerFactory.getLogger(TenantResolverClient.class);

    private final WebClient webClient;
    private final GatewayProperties properties;
    private final GatewayRuntimeDefaultTenantService runtimeDefaultTenantService;

    public TenantResolverClient(
            WebClient webClient,
            GatewayProperties properties,
            GatewayRuntimeDefaultTenantService runtimeDefaultTenantService
    ) {
        this.webClient = webClient;
        this.properties = properties;
        this.runtimeDefaultTenantService = runtimeDefaultTenantService;
    }

    public Mono<TenantResolveResponse> resolveTenantIdByDomain(String domain) {
        if (!StringUtils.hasText(domain)) {
            return runtimeDefaultTenantService.resolveRuntimeDefaultTenantId("gateway_domain_empty")
                    .map(tenantId -> buildDefaultResponse(null, tenantId, "resolve_empty"));
        }

        String serviceId = properties.getBaseServiceId();
        String path = properties.getTenantResolvePath();
        String url = "http://" + serviceId + path;

        return webClient.get()
                .uri(URI.create(url + "?domain=" + encode(domain)))
                .retrieve()
                .onStatus(status -> status.isError(), resp -> resp.createException().flatMap(Mono::error))
                .bodyToMono(TenantResolveResponse.class)
                .onErrorResume(e -> fallbackIfAllowed(domain, e));
    }

    private Mono<TenantResolveResponse> fallbackIfAllowed(String domain, Throwable e) {
        if (properties.isFailOnTenantResolveError()) {
            return Mono.error(e);
        }
        return runtimeDefaultTenantService.resolveRuntimeDefaultTenantId("gateway_domain_resolve_error")
                .map(tenantId -> {
                    String reason = "resolve_error";
                    if (e instanceof WebClientResponseException w) {
                        reason = "resolve_error:" + w.getStatusCode().value();
                    }
                    log.warn("租户解析失败，已走运行时默认租户：domain={}, tenantId={}, failOnError={}, err={}",
                            domain, tenantId, properties.isFailOnTenantResolveError(), e.toString());
                    return buildDefaultResponse(reason, tenantId, reason);
                });
    }

    private static TenantResolveResponse buildDefaultResponse(String domain, long tenantId, String marker) {
        TenantResolveResponse r = new TenantResolveResponse();
        r.setTenantId(tenantId);
        r.setDomain(StringUtils.hasText(domain) ? domain : marker);
        r.setFromDefault(true);
        return r;
    }

    private static String encode(String s) {
        // 最小编码：避免引入额外依赖；domain 理论上只有 host，不应包含特殊字符
        return s.replace(" ", "%20");
    }
}
