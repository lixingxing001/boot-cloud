package com.bootcloud.web.core.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorHttpStatusMapper;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * boot-cloud-web 统一响应包装（ApiResponse）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该 BFF 面向前端使用，统一返回 ApiResponse，便于前端做一致的成功/失败处理。</li>
 *   <li>注意：boot-cloud-web 不提供 OAuth2 标准端点，因此这里无需排除 /oauth/**。</li>
 * </ul>
 */
@Slf4j
@RestControllerAdvice
public class WebApiResponseAdvice implements ResponseBodyAdvice<Object> {

    private final ErrorMessageResolver errorMessageResolver;

    public WebApiResponseAdvice(ErrorMessageResolver errorMessageResolver) {
        this.errorMessageResolver = errorMessageResolver;
    }

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
        // String 返回值容易被 StringHttpMessageConverter 处理，包装会导致内容协商/编码问题；这里不自动包装。
        if (body instanceof String) {
            return body;
        }
        // 3xx/204 等场景通常不需要响应体（例如 302 跳转），避免强行写入 ApiResponse 影响客户端行为。
        if (response instanceof ServletServerHttpResponse s) {
            int status = s.getServletResponse().getStatus();
            if ((status >= 300 && status < 400) || status == 204) {
                return body;
            }
        }
        String path = resolvePath(request);
        // 说明：actuator 属于运维接口，保持 Spring Boot 原生返回结构，避免影响探针/监控。
        if (path.startsWith("/actuator")) {
            return body;
        }

        // BFF 登录与刷新接口会拿到认证中心的 OAuth 错误体。
        // 这里把“上游错误 JSON”改写为统一 ApiResponse 失败结构，避免出现 success=true 但 data.error!=null 的语义冲突。
        ApiResponse<Object> oauthErrorResponse = tryRewriteOauthError(body, path, request, response);
        if (oauthErrorResponse != null) {
            return oauthErrorResponse;
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

    private ApiResponse<Object> tryRewriteOauthError(
            Object body,
            String path,
            ServerHttpRequest request,
            ServerHttpResponse response
    ) {
        if (!(body instanceof JsonNode node) || !isBffOauthTokenEndpoint(path)) {
            return null;
        }
        String code = text(node, "error");
        if (!StringUtils.hasText(code) || node.hasNonNull("access_token")) {
            return null;
        }

        String oauthDescription = firstNonBlank(
                text(node, "error_description"),
                text(node, "errorDescription")
        );
        Object requestObj = request instanceof ServletServerHttpRequest s
                ? s.getServletRequest()
                : request;

        String message;
        String localizedLookupCode;
        if (StringUtils.hasText(oauthDescription)) {
            // 优先按细粒度原因码本地化。
            // 若上游返回自由文本，这里先归一化为标准错误码再本地化。
            localizedLookupCode = normalizeOauthDescriptionCode(oauthDescription);
            message = errorMessageResolver.resolveByCode(requestObj, localizedLookupCode, oauthDescription);
        } else {
            // 无细分原因时，按 OAuth 主错误码本地化。
            localizedLookupCode = code;
            message = errorMessageResolver.resolveByCode(requestObj, code, code);
        }

        // 当前接口已经是 BFF 业务接口，对前端优先透出细粒度业务错误码。
        String publicCode = resolvePublicOauthCode(code, localizedLookupCode);

        if (StringUtils.hasText(publicCode) && !publicCode.equals(code)) {
            log.debug("BFF OAuth 细粒度错误码生效：path={}, upstreamCode={}, publicCode={}", path, code, publicCode);
        }
        if (CommonErrorCode.TENANT_NOT_ALLOWED.code().equals(publicCode)
                || CommonErrorCode.TENANT_DISABLED.code().equals(publicCode)) {
            log.warn("BFF OAuth 请求命中租户访问限制：path={}, publicCode={}, upstreamCode={}, desc={}",
                    path, publicCode, code, oauthDescription);
        }
        String traceId = text(node, "traceId");

        Map<String, Object> upstream = new LinkedHashMap<>();
        Integer upstreamStatus = intValue(node, "status");
        if (upstreamStatus != null) {
            upstream.put("status", upstreamStatus);
        }
        if (StringUtils.hasText(code)) {
            upstream.put("code", code);
        }
        if (StringUtils.hasText(oauthDescription)) {
            upstream.put("message", oauthDescription);
        }

        HttpStatus status = ErrorHttpStatusMapper.resolveByCode(publicCode);
        if (response instanceof ServletServerHttpResponse s) {
            s.getServletResponse().setStatus(status.value());
        }

        if (log.isDebugEnabled()) {
            log.debug("BFF OAuth 错误已改写：path={}, status={}, upstreamCode={}, publicCode={}, desc={}, lookupCode={}, localizedMessage={}",
                    path, status.value(), code, publicCode, oauthDescription, localizedLookupCode, message);
        }
        Map<String, Object> details = buildStrictErrorDetails(
                traceId,
                publicCode,
                StringUtils.hasText(oauthDescription) ? oauthDescription : message,
                upstream,
                Map.of()
        );
        ApiResponse<Object> resp = ApiResponse.error(publicCode, message, details);
        resp.setPath(path);
        return resp;
    }

    /**
     * OAuth 细粒度描述归一化。
     *
     * <ul>
     *   <li>上游可能返回机器码，也可能返回英文自由文本。</li>
     *   <li>为了让 Accept-Language 生效，这里优先把自由文本归一化为统一错误码。</li>
     * </ul>
     */
    private static String normalizeOauthDescriptionCode(String oauthDescription) {
        if (!StringUtils.hasText(oauthDescription)) {
            return "";
        }
        String desc = oauthDescription.trim();
        if (CommonErrorCode.known(desc)) {
            return CommonErrorCode.canonicalCode(desc);
        }

        String lower = desc.toLowerCase();
        // 这里把认证中心返回的自由文本继续归一化成稳定错误码。
        if ("tenant is not allowed".equals(lower)) {
            return CommonErrorCode.TENANT_NOT_ALLOWED.code();
        }
        if ("tenant is disabled".equals(lower)) {
            return CommonErrorCode.TENANT_DISABLED.code();
        }
        if ("account_disabled".equals(lower)
                || "account is disabled".equals(lower)
                || "admin account is disabled".equals(lower)) {
            return CommonErrorCode.ACCOUNT_DISABLED.code();
        }
        if (lower.contains("invalid username or password")
                || lower.contains("bad credentials")
                || lower.contains("invalid credentials")) {
            return CommonErrorCode.INVALID_CREDENTIALS.code();
        }
        if (lower.contains("otp required")) {
            return CommonErrorCode.OTP_REQUIRED.code();
        }
        if (lower.contains("invalid otp")
                || lower.contains("otp invalid")
                || lower.contains("otp expired")) {
            return CommonErrorCode.INVALID_OTP.code();
        }
        if (lower.contains("backup code")
                && (lower.contains("invalid") || lower.contains("expired"))) {
            return CommonErrorCode.BACKUP_CODE_INVALID.code();
        }
        return desc;
    }

    private static String resolvePublicOauthCode(String oauthCode, String localizedLookupCode) {
        if (StringUtils.hasText(localizedLookupCode) && CommonErrorCode.known(localizedLookupCode)) {
            return CommonErrorCode.canonicalCode(localizedLookupCode);
        }
        return StringUtils.hasText(oauthCode) ? oauthCode.trim() : CommonErrorCode.BAD_REQUEST.code();
    }

    /**
     * 构造严格协议的 error.details。
     *
     * <ul>
     *   <li>根字段固定为 traceId/reasonCode/reasonMessage/upstream/context。</li>
     *   <li>上游排障信息统一放入 upstream，避免再次出现平铺根字段。</li>
     * </ul>
     */
    private static Map<String, Object> buildStrictErrorDetails(
            String traceId,
            String reasonCode,
            String reasonMessage,
            Map<String, Object> upstream,
            Map<String, Object> context
    ) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("traceId", StringUtils.hasText(traceId) ? traceId.trim() : "");
        details.put("reasonCode", StringUtils.hasText(reasonCode) ? reasonCode.trim() : "");
        details.put("reasonMessage", StringUtils.hasText(reasonMessage) ? reasonMessage.trim() : "");
        details.put("upstream", upstream == null ? Map.of() : upstream);
        details.put("context", context == null ? Map.of() : context);
        return details;
    }

    private static boolean isBffOauthTokenEndpoint(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        String p = path.trim();
        return "/api/web/auth/password/token".equals(p)
                || "/api/web/auth/oauth/token".equals(p)
                || "/api/web/auth/refresh".equals(p)
                || "/api/web/admin/auth/password/token".equals(p)
                || "/api/web/admin/auth/refresh".equals(p);
    }

    private static Object jsonNodeToValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isTextual()) {
            return node.asText();
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isIntegralNumber()) {
            return node.longValue();
        }
        if (node.isFloatingPointNumber()) {
            return node.doubleValue();
        }
        return node;
    }

    private static String text(JsonNode node, String fieldName) {
        if (node == null || !node.hasNonNull(fieldName)) {
            return "";
        }
        return node.get(fieldName).asText("");
    }

    private static Integer intValue(JsonNode node, String fieldName) {
        if (node == null || !node.has(fieldName)) {
            return null;
        }
        JsonNode valueNode = node.get(fieldName);
        if (valueNode != null && valueNode.canConvertToInt()) {
            return valueNode.asInt();
        }
        return null;
    }

    private static String firstNonBlank(String... values) {
        if (values == null || values.length == 0) {
            return "";
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }
}
