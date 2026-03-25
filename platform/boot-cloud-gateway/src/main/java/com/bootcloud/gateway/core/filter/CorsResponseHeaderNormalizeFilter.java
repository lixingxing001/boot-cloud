package com.bootcloud.gateway.core.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * CORS 响应头规范化过滤器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当前网关开启 CORS 后，会根据请求 Origin 追加 {@code Access-Control-Allow-Origin}。</li>
 *   <li>下游服务如果也设置了 CORS（常见为 {@code *}），浏览器会收到多个值，直接判定 CORS 失败。</li>
 *   <li>该过滤器在响应提交前做一次“去重与取舍”，确保响应头里只保留一个合法的 Origin。</li>
 * </ul>
 *
 * <p>重点：</p>
 * <ul>
 *   <li>如果同时存在请求 Origin 与 {@code *}，优先保留请求 Origin，避免浏览器报 “multiple values”。</li>
 *   <li>该逻辑对 dev 与 prod 都安全，属于防御性修正。</li>
 * </ul>
 */
@Component
public class CorsResponseHeaderNormalizeFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(CorsResponseHeaderNormalizeFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // beforeCommit 确保在响应真正写出前还能修改 header
        exchange.getResponse().beforeCommit(() -> {
            normalize(exchange);
            return Mono.empty();
        });
        return chain.filter(exchange);
    }

    private void normalize(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getResponse().getHeaders();
        List<String> allowOrigin = headers.get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
        if (CollectionUtils.isEmpty(allowOrigin) || allowOrigin.size() <= 1) {
            return;
        }

        String origin = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ORIGIN);
        String path = exchange.getRequest().getURI().getPath();

        String chosen = chooseAllowOrigin(origin, allowOrigin);
        if (!StringUtils.hasText(chosen)) {
            return;
        }

        headers.put(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, List.of(chosen));

        // Allow-Credentials 出现多个值时也做一次去重，优先 true
        List<String> credentials = headers.get(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);
        if (!CollectionUtils.isEmpty(credentials) && credentials.size() > 1) {
            boolean anyTrue = credentials.stream().anyMatch(v -> "true".equalsIgnoreCase(String.valueOf(v).trim()));
            headers.put(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, List.of(anyTrue ? "true" : "false"));
        }

        // Vary 可能被重复追加，做一次去重
        List<String> vary = headers.get(HttpHeaders.VARY);
        if (!CollectionUtils.isEmpty(vary) && vary.size() > 1) {
            Set<String> uniq = new LinkedHashSet<>();
            for (String v : vary) {
                if (!StringUtils.hasText(v)) {
                    continue;
                }
                // 有的框架会把多个 vary 合并成逗号分隔字符串
                for (String part : v.split(",")) {
                    String p = part.trim();
                    if (StringUtils.hasText(p)) {
                        uniq.add(p);
                    }
                }
            }
            if (!uniq.isEmpty()) {
                headers.put(HttpHeaders.VARY, new ArrayList<>(uniq));
            }
        }

        log.debug("CORS 响应头已规范化，path={}，origin={}，allowOriginRaw={}，chosen={}",
                path, origin, allowOrigin, chosen);
    }

    private static String chooseAllowOrigin(String requestOrigin, List<String> allowOrigin) {
        // 1) 请求带 Origin 且响应头里包含该 Origin，优先返回
        if (StringUtils.hasText(requestOrigin)) {
            for (String v : allowOrigin) {
                if (requestOrigin.equals(v)) {
                    return requestOrigin;
                }
            }
        }

        // 2) 如果包含 * 且请求带 Origin，优先返回请求 Origin
        // 说明：浏览器会拒绝 "Origin, *" 的组合，这里把它修正为单一值
        boolean hasStar = allowOrigin.stream().anyMatch(v -> "*".equals(String.valueOf(v).trim()));
        if (hasStar && StringUtils.hasText(requestOrigin)) {
            return requestOrigin;
        }

        // 3) 兜底：取第一个非空值
        for (String v : allowOrigin) {
            if (StringUtils.hasText(v)) {
                return v.trim();
            }
        }
        return null;
    }

    @Override
    public int getOrder() {
        // 尽量靠后执行，确保拿到下游与网关最终合并后的 header 再规范化
        return Ordered.LOWEST_PRECEDENCE;
    }
}

