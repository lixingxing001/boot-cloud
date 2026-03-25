package com.bootcloud.gateway.core.error;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.trace.TraceProperties;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 说明：
 * 网关全局异常处理器回归测试，覆盖“上游 4xx 业务码透传”关键分支。
 * 目标是避免未来改动把业务码再次误判成通用 invalid_request。
 */
class GatewayGlobalErrorHandlerTest {

    @Test
    void classifyError_shouldMapTenantNotAllowedToForbidden() {
        GatewayGlobalErrorHandler handler = newHandler();
        WebClientResponseException ex = badRequest("{\"error\":{\"code\":\"tenant_not_allowed\",\"message\":\"当前租户未被允许登录\"}}");

        Object decision = ReflectionTestUtils.invokeMethod(handler, "classifyError", ex);

        assertNotNull(decision);
        assertEquals(HttpStatus.FORBIDDEN, ReflectionTestUtils.invokeMethod(decision, "status"));
        assertEquals("tenant_not_allowed", ReflectionTestUtils.invokeMethod(decision, "error"));
        assertEquals("当前租户未被允许登录", ReflectionTestUtils.invokeMethod(decision, "description"));
        @SuppressWarnings("unchecked")
        Map<String, Object> details = (Map<String, Object>) ReflectionTestUtils.invokeMethod(decision, "details");
        assertEquals(400, details.get("upstreamStatus"));
        assertEquals("tenant_not_allowed", details.get("upstreamCode"));
    }

    @Test
    void classifyError_shouldMapTenantDisabledFromStringError() {
        GatewayGlobalErrorHandler handler = newHandler();
        WebClientResponseException ex = badRequest("{\"error\":\"tenant_disabled\",\"error_description\":\"tenant is disabled\"}");

        Object decision = ReflectionTestUtils.invokeMethod(handler, "classifyError", ex);

        assertNotNull(decision);
        assertEquals(HttpStatus.FORBIDDEN, ReflectionTestUtils.invokeMethod(decision, "status"));
        assertEquals("tenant_disabled", ReflectionTestUtils.invokeMethod(decision, "error"));
        assertEquals("tenant is disabled", ReflectionTestUtils.invokeMethod(decision, "description"));
    }

    @Test
    void classifyError_shouldKeepBadRequestWhenMappedStatusIsServerError() {
        GatewayGlobalErrorHandler handler = newHandler();
        WebClientResponseException ex = badRequest("{\"error\":{\"code\":\"service_unavailable\",\"message\":\"upstream down\"}}");

        Object decision = ReflectionTestUtils.invokeMethod(handler, "classifyError", ex);

        assertNotNull(decision);
        // 上游返回 4xx 时，即便错误码映射到 5xx，也要保持 400 语义，避免误导调用方。
        assertEquals(HttpStatus.BAD_REQUEST, ReflectionTestUtils.invokeMethod(decision, "status"));
        assertEquals("service_unavailable", ReflectionTestUtils.invokeMethod(decision, "error"));
        assertEquals("upstream down", ReflectionTestUtils.invokeMethod(decision, "description"));
    }

    @Test
    void classifyError_shouldPassThroughUnknownBusinessCode() {
        GatewayGlobalErrorHandler handler = newHandler();
        WebClientResponseException ex = badRequest("{\"error\":{\"code\":\"foo_bar\",\"message\":\"foo message\"}}");

        Object decision = ReflectionTestUtils.invokeMethod(handler, "classifyError", ex);

        assertNotNull(decision);
        assertEquals(HttpStatus.BAD_REQUEST, ReflectionTestUtils.invokeMethod(decision, "status"));
        assertEquals("foo_bar", ReflectionTestUtils.invokeMethod(decision, "error"));
        assertEquals("foo message", ReflectionTestUtils.invokeMethod(decision, "description"));
    }

    private static GatewayGlobalErrorHandler newHandler() {
        return new GatewayGlobalErrorHandler(new ObjectMapper(), new TraceProperties(), null);
    }

    private static WebClientResponseException badRequest(String body) {
        return WebClientResponseException.create(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                HttpHeaders.EMPTY,
                body.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );
    }
}
