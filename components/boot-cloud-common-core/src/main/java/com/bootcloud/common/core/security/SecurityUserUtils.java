package com.bootcloud.common.core.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 当前登录用户工具类（业务层入口）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当前阶段：主要从网关注入的 Header 获取（由 SecurityUserContextFilter 写入 ThreadLocal）。</li>
 *   <li>未来阶段：当服务升级为标准 OAuth2 资源服务后，本类会优先从 Spring SecurityContext 获取。</li>
 *   <li>业务代码建议统一使用本类，避免在 Controller Service 到处解析 Header。</li>
 * </ul>
 */
public final class SecurityUserUtils {

    private static final Logger log = LoggerFactory.getLogger(SecurityUserUtils.class);

    private SecurityUserUtils() {
    }

    /**
     * 获取当前用户上下文（可能为空）。
     */
    public static SecurityUserContext getContext() {
        SecurityUserContext fromSecurity = tryResolveFromSpringSecurity();
        SecurityUserContext fromHeader = SecurityUserContextHolder.get();
        return mergeContexts(fromSecurity, fromHeader);
    }

    public static Optional<String> getUserIdStr() {
        SecurityUserContext ctx = getContext();
        return Optional.ofNullable(ctx == null ? null : ctx.getUserId());
    }

    public static Optional<Long> getUserId() {
        return getUserIdStr().flatMap(SecurityUserUtils::tryParseLong);
    }

    public static Long requireUserId() {
        return getUserId().orElseThrow(() -> new IllegalStateException("缺少用户信息，请确认请求已通过网关鉴权并注入 X-User-Id"));
    }

    public static Optional<String> getTenantIdStr() {
        SecurityUserContext ctx = getContext();
        return Optional.ofNullable(ctx == null ? null : ctx.getTenantId());
    }

    public static Optional<Long> getTenantId() {
        return getTenantIdStr().flatMap(SecurityUserUtils::tryParseLong);
    }

    public static Long requireTenantId() {
        return getTenantId().orElseThrow(() -> new IllegalStateException("缺少租户信息，请确认请求已通过网关租户解析并注入 X-Tenant-Id"));
    }

    public static Optional<String> getClientId() {
        SecurityUserContext ctx = getContext();
        return Optional.ofNullable(ctx == null ? null : ctx.getClientId());
    }

    public static Set<String> getScopes() {
        SecurityUserContext ctx = getContext();
        return ctx == null ? Collections.emptySet() : ctx.getScopes();
    }

    public static boolean hasScope(String scope) {
        SecurityUserContext ctx = getContext();
        return ctx != null && ctx.hasScope(scope);
    }

    private static Optional<Long> tryParseLong(String s) {
        if (s == null || s.isBlank()) return Optional.empty();
        try {
            return Optional.of(Long.parseLong(s.trim()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * 合并 Spring Security 与 Header ThreadLocal 上下文。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>Spring Security principal 更适合承载 userId 和 scopes。</li>
     *   <li>当前后台 Bearer introspection 未必总会返回 tenant_id/client_id。</li>
     *   <li>因此 tenantId/clientId 缺失时，需要回退到网关注入的 Header 上下文。</li>
     * </ul>
     */
    private static SecurityUserContext mergeContexts(SecurityUserContext fromSecurity, SecurityUserContext fromHeader) {
        if (fromSecurity == null) {
            return fromHeader;
        }
        if (fromHeader == null) {
            return fromSecurity;
        }

        String userId = firstNonBlank(fromSecurity.getUserId(), fromHeader.getUserId());
        String tenantId = firstNonBlank(fromSecurity.getTenantId(), fromHeader.getTenantId());
        String clientId = firstNonBlank(fromSecurity.getClientId(), fromHeader.getClientId());
        Set<String> scopes = !fromSecurity.getScopes().isEmpty() ? fromSecurity.getScopes() : fromHeader.getScopes();

        if (log.isDebugEnabled() && (isBlank(fromSecurity.getTenantId()) || isBlank(fromSecurity.getClientId()))) {
            log.debug("SecurityUserContext 合并回退：securityTenantId={}, headerTenantId={}, securityClientId={}, headerClientId={}, resolvedTenantId={}, resolvedClientId={}",
                    safe(fromSecurity.getTenantId()),
                    safe(fromHeader.getTenantId()),
                    safe(fromSecurity.getClientId()),
                    safe(fromHeader.getClientId()),
                    safe(tenantId),
                    safe(clientId));
        }

        return new SecurityUserContext(userId, tenantId, clientId, scopes);
    }

    /**
     * 尝试从 Spring Security 的 SecurityContext 获取信息。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>为了避免让 boot-cloud-common-core 强依赖 Spring Security，这里使用反射。</li>
     *   <li>当服务未引入 Spring Security 或未启用资源服务时，本方法会返回 null。</li>
     * </ul>
     */
    @SuppressWarnings("unchecked")
    private static SecurityUserContext tryResolveFromSpringSecurity() {
        Object authentication = null;
        try {
            Class<?> holderClass = Class.forName("org.springframework.security.core.context.SecurityContextHolder");
            Method getContext = holderClass.getMethod("getContext");
            Object context = getContext.invoke(null);
            if (context == null) return null;

            Method getAuth = context.getClass().getMethod("getAuthentication");
            authentication = getAuth.invoke(context);
            if (authentication == null) return null;

            Method isAuthenticated = authentication.getClass().getMethod("isAuthenticated");
            Object authed = isAuthenticated.invoke(authentication);
            if (authed instanceof Boolean b && !b) return null;

            Map<String, Object> attributes = resolveAttributes(authentication);
            if (attributes == null || attributes.isEmpty()) return null;

            String userId = firstString(attributes, "user_id", "userId", "uid", "sub", "id");
            String tenantId = firstString(attributes, "tenant_id", "tenantId");
            String clientId = firstString(attributes, "client_id", "clientId");
            Set<String> scopes = resolveScopes(attributes);

            if (userId == null && tenantId == null && clientId == null && scopes.isEmpty()) return null;
            return new SecurityUserContext(userId, tenantId, clientId, scopes);
        } catch (ClassNotFoundException e) {
            return null;
        } catch (Exception e) {
            // 反射读取失败时，直接降级到 Header ThreadLocal
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> resolveAttributes(Object authentication) {
        try {
            Method getPrincipal = authentication.getClass().getMethod("getPrincipal");
            Object principal = getPrincipal.invoke(authentication);
            if (principal == null) return null;

            if (principal instanceof Map<?, ?> map) {
                return (Map<String, Object>) map;
            }

            // OAuth2AuthenticatedPrincipal.getAttributes()
            Method getAttributes = tryMethod(principal.getClass(), "getAttributes");
            if (getAttributes != null) {
                Object attrs = getAttributes.invoke(principal);
                if (attrs instanceof Map<?, ?> map) {
                    return (Map<String, Object>) map;
                }
            }

            // Jwt.getClaims()
            Method getClaims = tryMethod(principal.getClass(), "getClaims");
            if (getClaims != null) {
                Object claims = getClaims.invoke(principal);
                if (claims instanceof Map<?, ?> map) {
                    return (Map<String, Object>) map;
                }
            }

            // JwtAuthenticationToken.getToken().getClaims()
            Method getToken = tryMethod(authentication.getClass(), "getToken");
            if (getToken != null) {
                Object token = getToken.invoke(authentication);
                if (token != null) {
                    Method tokenClaims = tryMethod(token.getClass(), "getClaims");
                    if (tokenClaims != null) {
                        Object claims = tokenClaims.invoke(token);
                        if (claims instanceof Map<?, ?> map) {
                            return (Map<String, Object>) map;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private static Method tryMethod(Class<?> c, String name) {
        try {
            return c.getMethod(name);
        } catch (Exception e) {
            return null;
        }
    }

    private static String firstString(Map<String, Object> attrs, String... keys) {
        if (attrs == null || attrs.isEmpty()) return null;
        for (String k : keys) {
            Object v = attrs.get(k);
            String s = toStr(v);
            if (s != null) return s;
        }
        return null;
    }

    private static String toStr(Object v) {
        if (v == null) return null;
        if (v instanceof String s) {
            String t = s.trim();
            return t.isEmpty() ? null : t;
        }
        return String.valueOf(v).trim();
    }

    private static Set<String> resolveScopes(Map<String, Object> attrs) {
        Object raw = attrs.get("scope");
        if (raw == null) raw = attrs.get("scp");
        if (raw == null) return Collections.emptySet();

        if (raw instanceof String s) {
            return SecurityUserContextFilter.parseScopes(s);
        }
        if (raw instanceof Collection<?> c) {
            StringBuilder sb = new StringBuilder();
            for (Object item : c) {
                if (item == null) continue;
                String v = String.valueOf(item).trim();
                if (v.isEmpty()) continue;
                if (sb.length() > 0) sb.append(' ');
                sb.append(v);
            }
            return SecurityUserContextFilter.parseScopes(sb.toString());
        }
        return SecurityUserContextFilter.parseScopes(String.valueOf(raw));
    }

    private static String firstNonBlank(String preferred, String fallback) {
        return !isBlank(preferred) ? preferred.trim() : (isBlank(fallback) ? null : fallback.trim());
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }
}
