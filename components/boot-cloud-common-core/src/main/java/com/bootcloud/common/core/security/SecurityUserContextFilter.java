package com.bootcloud.common.core.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * SecurityUser 上下文初始化 Filter。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>从请求 Header 中读取 userId tenantId clientId scopes，写入 ThreadLocal。</li>
 *   <li>同时写入 MDC，便于业务日志定位。</li>
 *   <li>不读取 token，不输出 token。</li>
 * </ul>
 */
public class SecurityUserContextFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(SecurityUserContextFilter.class);

    private static final String MDC_USER_ID = "userId";
    private static final String MDC_TENANT_ID = "tenantId";
    private static final String MDC_CLIENT_ID = "clientId";
    private static final String MDC_SCOPES = "scopes";

    private final SecurityUserProperties properties;

    public SecurityUserContextFilter(SecurityUserProperties properties) {
        this.properties = properties;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest req)) {
            chain.doFilter(request, response);
            return;
        }

        String userId = header(req, properties.getUserIdHeader());
        String tenantId = header(req, properties.getTenantIdHeader());
        String clientId = header(req, properties.getClientIdHeader());
        Set<String> scopes = parseScopes(header(req, properties.getScopeHeader()));

        SecurityUserContextHolder.set(new SecurityUserContext(userId, tenantId, clientId, scopes));

        if (userId != null) MDC.put(MDC_USER_ID, userId);
        if (tenantId != null) MDC.put(MDC_TENANT_ID, tenantId);
        if (clientId != null) MDC.put(MDC_CLIENT_ID, clientId);
        if (!scopes.isEmpty()) MDC.put(MDC_SCOPES, String.join(",", scopes));

        if (properties.isDebugLog()) {
            log.debug("SecurityUserContext 初始化：path={}, userId={}, tenantId={}, clientId={}, scopes={}",
                    req.getRequestURI(), userId, tenantId, clientId, scopes);
        }

        try {
            chain.doFilter(request, response);
        } finally {
            SecurityUserContextHolder.clear();
            MDC.remove(MDC_USER_ID);
            MDC.remove(MDC_TENANT_ID);
            MDC.remove(MDC_CLIENT_ID);
            MDC.remove(MDC_SCOPES);
        }
    }

    private static String header(HttpServletRequest req, String name) {
        if (name == null || name.isBlank()) return null;
        String v = req.getHeader(name);
        if (v == null) return null;
        String s = v.trim();
        return s.isEmpty() ? null : s;
    }

    /**
     * scope 解析，兼容空格与逗号两种分隔。
     */
    static Set<String> parseScopes(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        String normalized = raw.replace(',', ' ');
        String[] parts = normalized.trim().split("\\s+");
        Set<String> scopes = new LinkedHashSet<>();
        for (String p : parts) {
            if (p == null) continue;
            String v = p.trim();
            if (!v.isEmpty()) scopes.add(v);
        }
        return scopes;
    }
}
