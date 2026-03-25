package com.bootcloud.base.core.web;

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
 * boot-cloud-base 统一响应包装（仅对 /internal/admin/** 生效）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>/internal/tenant/**：给网关调用的“内部契约接口”，返回结构要稳定，避免再包一层。</li>
 *   <li>/internal/admin/**：给运维/后台使用的管理接口，统一使用 ApiResponse 包装，便于前端一致处理。</li>
 * </ul>
 */
@Slf4j
@RestControllerAdvice
public class BaseApiResponseAdvice implements ResponseBodyAdvice<Object> {

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
        if (!path.startsWith("/internal/admin/")) {
            return body;
        }
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
