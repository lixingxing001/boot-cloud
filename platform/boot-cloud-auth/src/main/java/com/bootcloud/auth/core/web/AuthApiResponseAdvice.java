package com.bootcloud.auth.core.web;

import com.bootcloud.common.core.api.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * boot-cloud-auth 非 OAuth 标准端点的统一响应包装（ApiResponse）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot-cloud-auth 同时承担两类接口：</li>
 *   <li>1) OAuth2 标准端点：<code>/oauth/**</code>（必须保持标准协议结构，不做 ApiResponse 包装）</li>
 *   <li>2) 认证扩展端点：<code>/api/auth/**</code>（统一使用 ApiResponse 包装）</li>
 * </ul>
 */
@Slf4j
@RestControllerAdvice
public class AuthApiResponseAdvice implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(
            Object body,
            MethodParameter returnType,
            MediaType selectedContentType,
            Class selectedConverterType,
            ServerHttpRequest request,
            ServerHttpResponse response
    ) {
        if (body instanceof ApiResponse) {
            return body;
        }
        String path = resolvePath(request);
        // actuator 属于运维接口，保持原生结构
        if (path.startsWith("/actuator")) {
            return body;
        }
        // /oauth/** 必须保持标准 OAuth2 协议返回
        if (path.startsWith("/oauth/")) {
            return body;
        }
        // String 返回值不自动包装（避免 StringHttpMessageConverter 导致的内容协商问题）
        if (body instanceof String) {
            return body;
        }
        if (log.isDebugEnabled()) {
            log.debug("响应包装：path={}, bodyType={}", path, body == null ? "null" : body.getClass().getName());
        }
        return ApiResponse.success(body, path);
    }

    private static String resolvePath(ServerHttpRequest request) {
        if (request instanceof ServletServerHttpRequest s) {
            return s.getServletRequest().getRequestURI();
        }
        return request.getURI().getPath();
    }
}
