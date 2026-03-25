package com.bootcloud.auth.core.tenant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 在进入 OAuth 端点前写入 {@link TenantContext}，并在请求结束后清理。
 *
 * <p>为什么要做拦截器而不是 Filter？</p>
 * <ul>
 *   <li>TenantResolver 可能抛出 {@code OAuthException}，拦截器抛出的异常更容易被 {@code @RestControllerAdvice} 捕获并返回统一格式。</li>
 *   <li>同时可以精确指定只拦截 {@code /oauth/**}，避免影响 actuator 等公共端点。</li>
 * </ul>
 */
public class TenantContextInterceptor implements HandlerInterceptor {

    private final TenantResolver tenantResolver;

    public TenantContextInterceptor(TenantResolver tenantResolver) {
        this.tenantResolver = tenantResolver;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        long tenantId = tenantResolver.resolveTenantId(request);
        TenantContext.setTenantId(tenantId);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        TenantContext.clear();
    }
}

