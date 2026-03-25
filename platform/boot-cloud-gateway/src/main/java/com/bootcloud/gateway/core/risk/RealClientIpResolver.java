package com.bootcloud.gateway.core.risk;

import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * 客户端真实 IP 解析器。
 */
public final class RealClientIpResolver {

    private RealClientIpResolver() {
    }

    /**
     * 解析客户端 IP。
     *
     * @param exchange 请求上下文
     * @param trustForwardedHeaders 是否信任转发头
     * @param headerCandidates 转发头优先级列表
     */
    public static String resolve(ServerWebExchange exchange, boolean trustForwardedHeaders, List<String> headerCandidates) {
        if (exchange == null || exchange.getRequest() == null) {
            return null;
        }
        HttpHeaders headers = exchange.getRequest().getHeaders();

        if (trustForwardedHeaders && headerCandidates != null) {
            for (String header : headerCandidates) {
                if (!StringUtils.hasText(header)) {
                    continue;
                }
                String raw = headers.getFirst(header.trim());
                String candidate = normalizeIp(firstToken(raw));
                if (isValidIp(candidate)) {
                    return candidate;
                }
            }
        }

        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        if (remote == null || remote.getAddress() == null) {
            return null;
        }
        return normalizeIp(remote.getAddress().getHostAddress());
    }

    private static String firstToken(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String v = raw.trim();
        int comma = v.indexOf(',');
        return comma > 0 ? v.substring(0, comma).trim() : v;
    }

    /**
     * 统一清洗 IP 文本，兼容 IPv4:port、[IPv6]:port。
     */
    private static String normalizeIp(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String v = raw.trim();
        if (v.startsWith("[") && v.contains("]")) {
            int end = v.indexOf(']');
            if (end > 1) {
                v = v.substring(1, end);
            }
            return v.trim();
        }
        // IPv4:port 场景
        if (v.indexOf(':') > 0 && v.indexOf('.') > 0 && v.indexOf(':') == v.lastIndexOf(':')) {
            return v.substring(0, v.indexOf(':')).trim();
        }
        return v;
    }

    private static boolean isValidIp(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        try {
            InetAddress.getByName(ip.trim());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

