package com.bootcloud.gateway.core.filter;

import com.bootcloud.gateway.config.GatewayPreferLocalLoadBalancerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

/**
 * 调用方 IP 注入过滤器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>目的：为 LoadBalancer 提供“调用方 IP”信息，实现从网关访问时优先命中调用方所在机器的实例。</li>
 *   <li>机制：计算调用方 IP 后写入内部 header（默认 X-BootCloud-Caller-Ip）。</li>
 *   <li>安全：外部传入的同名 header 会被覆盖，避免用户伪造。</li>
 * </ul>
 */
@Component
public class CallerIpInjectGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(CallerIpInjectGlobalFilter.class);

    private final GatewayPreferLocalLoadBalancerProperties props;

    public CallerIpInjectGlobalFilter(GatewayPreferLocalLoadBalancerProperties props) {
        this.props = props;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!props.isEnabled() || !props.isPreferCallerIp()) {
            return chain.filter(exchange);
        }

        String headerName = props.getCallerIpHeaderName();
        if (!StringUtils.hasText(headerName)) {
            return chain.filter(exchange);
        }

        String callerIp = resolveCallerIp(exchange);
        if (!StringUtils.hasText(callerIp)) {
            return chain.filter(exchange);
        }

        ServerHttpRequest mutatedReq = exchange.getRequest().mutate()
                .headers(h -> {
                    h.remove(headerName);
                    h.set(headerName, callerIp);
                })
                .build();

        if (log.isDebugEnabled()) {
            log.debug("已注入调用方 IP：path={}，callerIp={}，header={}",
                    exchange.getRequest().getURI().getPath(), callerIp, headerName);
        }

        return chain.filter(exchange.mutate().request(mutatedReq).build());
    }

    private String resolveCallerIp(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getRequest().getHeaders();

        if (props.isTrustForwardedHeaders()) {
            String xff = headers.getFirst("X-Forwarded-For");
            String xffIp = firstIpFromXff(xff);
            if (StringUtils.hasText(xffIp)) {
                return xffIp;
            }
            String xReal = headers.getFirst("X-Real-IP");
            if (StringUtils.hasText(xReal)) {
                return xReal.trim();
            }
        }

        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        if (remote == null || remote.getAddress() == null) {
            return null;
        }
        return remote.getAddress().getHostAddress();
    }

    private static String firstIpFromXff(String xff) {
        if (!StringUtils.hasText(xff)) {
            return null;
        }
        String v = xff.trim();
        int idx = v.indexOf(',');
        String first = idx > 0 ? v.substring(0, idx) : v;
        return first.trim();
    }

    @Override
    public int getOrder() {
        // 必须早于 ReactiveLoadBalancerClientFilter(10150) 执行，确保 header 已写入请求
        return 10100;
    }
}
