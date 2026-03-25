package com.bootcloud.gateway.core.filter;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.core.trace.TraceIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * 网关本地探活过滤器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于“访问受限卡片”的重试探活，不再依赖任意上游服务实例。</li>
 *   <li>执行顺序放在风控之后、鉴权之前，确保探活请求也会命中 IP/地区策略。</li>
 *   <li>探活成功只代表“网关入口已放行”，不会验证下游业务服务健康度。</li>
 * </ul>
 */
@Component
public class GatewayProbeGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(GatewayProbeGlobalFilter.class);
    private static final Set<String> PROBE_PATHS = Set.of(
            "/api/gateway/probe",
            "/api/admin/gateway/probe"
    );

    private final ObjectMapper mapper;

    public GatewayProbeGlobalFilter(ObjectMapper mapper) {
        this.mapper = mapper.copy().setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (!PROBE_PATHS.contains(path)) {
            return chain.filter(exchange);
        }
        String traceId = resolveTraceId(exchange);
        if (log.isDebugEnabled()) {
            log.debug("[gateway-probe] 探活通过：path={}, traceId={}", path, traceId);
        }

        exchange.getResponse().setStatusCode(HttpStatus.OK);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("status", "ok");
        data.put("service", "boot-cloud-gateway");
        data.put("traceId", traceId);
        ApiResponse<Map<String, Object>> body = ApiResponse.success(data, path);

        try {
            byte[] bytes = mapper.writeValueAsBytes(body);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        } catch (Exception e) {
            byte[] bytes = ("{\"success\":true,\"data\":{\"status\":\"ok\",\"service\":\"boot-cloud-gateway\",\"traceId\":\""
                    + safe(traceId) + "\"},\"path\":\"" + safe(path) + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        }
    }

    private static String resolveTraceId(ServerWebExchange exchange) {
        Object fromAttr = exchange.getAttributes().get(TraceIdContext.REACTOR_KEY);
        if (fromAttr != null && StringUtils.hasText(String.valueOf(fromAttr))) {
            return String.valueOf(fromAttr).trim();
        }
        String fromHeader = exchange.getRequest().getHeaders().getFirst("X-Trace-Id");
        if (StringUtils.hasText(fromHeader)) {
            return fromHeader.trim();
        }
        return TraceIdGenerator.generate();
    }

    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\"", "'");
    }

    @Override
    public int getOrder() {
        // 说明：保证顺序为 风控(-110) -> probe(-105) -> 鉴权(-100)。
        return -105;
    }
}

