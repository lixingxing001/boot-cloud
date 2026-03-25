package com.bootcloud.gateway.core.filter;

import com.bootcloud.common.core.trace.TraceProperties;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.core.trace.TraceIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 网关 TraceId 全局 Filter。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>网关作为链路入口，负责生成或复用 X-Trace-Id，并透传给下游。</li>
 *   <li>同时把 traceId 注入到 Reactor Context，供 WebClient 透传 filter 读取。</li>
 * </ul>
 */
public class TraceIdGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(TraceIdGlobalFilter.class);

    private final TraceProperties props;

    public TraceIdGlobalFilter(TraceProperties props) {
        this.props = props;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (props == null || !props.isEnabled()) {
            return chain.filter(exchange);
        }

        String headerName = StringUtils.hasText(props.getHeaderName()) ? props.getHeaderName().trim() : "X-Trace-Id";
        String incoming = exchange.getRequest().getHeaders().getFirst(headerName);
        String traceId = StringUtils.hasText(incoming) ? incoming.trim() : TraceIdGenerator.generate();

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(h -> h.set(headerName, traceId))
                .build();

        ServerHttpResponse response = exchange.getResponse();
        if (props.isEchoResponseHeader()) {
            // 说明：
            // 这里使用 beforeCommit 在响应最终提交前覆盖 header，避免下游服务也回写 X-Trace-Id 时出现重复头值。
            response.beforeCommit(() -> {
                response.getHeaders().set(headerName, traceId);
                return Mono.empty();
            });
        }

        // 说明：放入 exchange 属性，便于其它 Filter 读取
        exchange.getAttributes().put(TraceIdContext.REACTOR_KEY, traceId);

        if (log.isDebugEnabled() && !StringUtils.hasText(incoming)) {
            log.debug("网关已生成 traceId：path={}, traceId={}", exchange.getRequest().getURI().getPath(), traceId);
        }

        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
        return chain.filter(mutatedExchange).contextWrite(ctx -> ctx.put(TraceIdContext.REACTOR_KEY, traceId));
    }

    @Override
    public int getOrder() {
        // 说明：尽量靠前执行，保证后续 Filter 与 WebClient 调用能拿到 traceId
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}

