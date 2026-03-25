package com.bootcloud.gateway.core.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorHttpStatusMapper;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import com.bootcloud.common.core.trace.TraceProperties;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.core.trace.TraceIdGenerator;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 网关全局异常处理：将部分异常转换为 JSON 输出。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>例如：tenant header 非法、boot-cloud-base 解析失败且配置为 failOnTenantResolveError=true。</li>
 *   <li>避免默认的 HTML/白页响应，方便前端/调用方处理。</li>
 * </ul>
 */
@Component
@Order(-1)
public class GatewayGlobalErrorHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GatewayGlobalErrorHandler.class);
    private static final Pattern DOMAIN_NOT_MAPPED_PATTERN = Pattern.compile(
            "domain\\s+not\\s+mapped\\s*:\\s*([^\"\\s,}]+)",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern DOMAIN_QUERY_PATTERN = Pattern.compile("[?&]domain=([^&\\s]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern MISSING_INSTANCE_PATTERN = Pattern.compile(
            "unable\\s+to\\s+find\\s+instance\\s+for\\s+([a-zA-Z0-9._-]+)",
            Pattern.CASE_INSENSITIVE
    );

    private final ObjectMapper mapper;
    private final TraceProperties traceProperties;
    private final ErrorMessageResolver errorMessageResolver;

    public GatewayGlobalErrorHandler(
            ObjectMapper mapper,
            TraceProperties traceProperties,
            ErrorMessageResolver errorMessageResolver
    ) {
        this.mapper = mapper.copy().setSerializationInclusion(JsonInclude.Include.NON_NULL);
        this.traceProperties = traceProperties;
        this.errorMessageResolver = errorMessageResolver;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }

        String headerName = resolveTraceHeaderName();
        String traceId = resolveTraceId(exchange, headerName);
        String path = exchange.getRequest() == null || exchange.getRequest().getURI() == null
                ? ""
                : exchange.getRequest().getURI().getPath();

        ErrorDecision decision = classifyError(ex);
        HttpStatus status = decision.status();
        String error = decision.error();
        String description = decision.description();

        // 说明：
        // 这里强制把 traceId 回写到响应头，确保“异常响应”也能在浏览器与日志中被串联定位。
        exchange.getResponse().beforeCommit(() -> {
            exchange.getResponse().getHeaders().set(headerName, traceId);
            return Mono.empty();
        });

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // 说明：
        // /api/** 统一输出 ApiResponse；/oauth/** 保持协议风格，避免影响 OAuth 标准客户端。
        if (isApiPath(path) && !isOAuthPath(path)) {
            String code = resolveApiErrorCode(error);
            String localizedMessage = resolveLocalizedMessage(exchange, code, description);
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("traceId", traceId);
            if (!decision.details().isEmpty()) {
                details.putAll(decision.details());
            }
            ApiResponse<Void> body = ApiResponse.error(code, localizedMessage, details);
            body.setPath(path);
            if (log.isDebugEnabled()) {
                log.debug("网关全局异常统一输出：path={}, status={}, code={}, traceId={}",
                        path, status.value(), code, traceId);
            }
            logGatewayException(exchange, ex, traceId, status, code);
            try {
                byte[] bytes = mapper.writeValueAsBytes(body);
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            } catch (Exception e) {
                byte[] bytes = ("{\"success\":false,\"error\":{\"code\":\"" + safe(code)
                        + "\",\"message\":\"" + safe(localizedMessage)
                        + "\",\"details\":{\"traceId\":\"" + safe(traceId)
                        + "\"}},\"path\":\"" + safe(path) + "\"}")
                        .getBytes(StandardCharsets.UTF_8);
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            }
        }

        ErrorBody body = new ErrorBody();
        body.error = error;
        body.errorDescription = StringUtils.hasText(description) ? description : "error";
        body.traceId = traceId;

        logGatewayException(exchange, ex, traceId, status, error);

        try {
            byte[] bytes = mapper.writeValueAsBytes(body);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        } catch (Exception e) {
            byte[] bytes = ("{\"error\":\"" + error + "\",\"error_description\":\"" + safe(body.errorDescription) + "\",\"traceId\":\"" + safe(traceId) + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        }
    }

    private String resolveTraceHeaderName() {
        if (traceProperties != null && StringUtils.hasText(traceProperties.getHeaderName())) {
            return traceProperties.getHeaderName().trim();
        }
        return "X-Trace-Id";
    }

    private String resolveTraceId(ServerWebExchange exchange, String headerName) {
        String incoming = exchange.getRequest().getHeaders().getFirst(headerName);
        if (StringUtils.hasText(incoming)) {
            return incoming.trim();
        }

        Object fromAttr = exchange.getAttributes().get(TraceIdContext.REACTOR_KEY);
        if (fromAttr != null && StringUtils.hasText(String.valueOf(fromAttr))) {
            return String.valueOf(fromAttr).trim();
        }

        // 说明：兜底生成一个 traceId，确保至少能定位到“网关侧异常”。
        return TraceIdGenerator.generate();
    }

    private void logGatewayException(ServerWebExchange exchange, Throwable ex, String traceId, HttpStatus status, String code) {
        try {
            String method = exchange.getRequest().getMethod() == null ? "UNKNOWN" : exchange.getRequest().getMethod().name();
            String path = exchange.getRequest().getURI().getPath();
            String query = exchange.getRequest().getURI().getRawQuery();

            MultiValueMap<String, String> headers = exchange.getRequest().getHeaders();
            String tenantId = headers.getFirst("X-Tenant-Id");
            boolean hasAuth = StringUtils.hasText(headers.getFirst("Authorization"));

            // 说明：
            // 这里不输出 Authorization 具体值，避免 token 泄露；仅输出是否携带，用于排障。
            if (status != null && status.is4xxClientError()) {
                log.warn("网关捕获业务异常：traceId={}，method={}，path={}，query={}，status={}，code={}，tenantId={}，hasAuthorization={}，msg={}",
                        traceId, method, path, query, status.value(), code, tenantId, hasAuth, ex == null ? "" : ex.getMessage());
                return;
            }
            log.error("网关捕获异常：traceId={}，method={}，path={}，query={}，status={}，code={}，tenantId={}，hasAuthorization={}，msg={}",
                    traceId, method, path, query, status == null ? null : status.value(), code, tenantId, hasAuth,
                    ex == null ? "" : ex.getMessage(), ex);
        } catch (Exception logEx) {
            log.error("网关异常日志输出失败：traceId={}，msg={}", traceId, logEx.getMessage());
        }
    }

    private String resolveLocalizedMessage(ServerWebExchange exchange, String code, String fallbackMessage) {
        if (errorMessageResolver == null || exchange == null || exchange.getRequest() == null) {
            return fallbackMessage;
        }
        String localized = errorMessageResolver.resolveByCode(exchange.getRequest(), code, fallbackMessage);
        return StringUtils.hasText(localized) ? localized : fallbackMessage;
    }

    private static String resolveApiErrorCode(String gatewayError) {
        String normalized = CommonErrorCode.canonicalCode(gatewayError);
        if (CommonErrorCode.known(normalized)) {
            return normalized;
        }
        if ("invalid_request".equalsIgnoreCase(gatewayError)) {
            return CommonErrorCode.INVALID_REQUEST.code();
        }
        return CommonErrorCode.SERVER_ERROR.code();
    }

    private ErrorDecision classifyError(Throwable ex) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String error = "gateway_error";
        String description = ex == null ? "unknown error" : ex.getMessage();
        Map<String, Object> details = new LinkedHashMap<>();

        // 说明：
        // 通过服务发现找不到上游实例时，返回明确维护语义和可观测细节，避免被兜底成 server_error。
        if (ex instanceof NotFoundException nfe && isMissingServiceInstance(nfe.getMessage())) {
            details.put("upstreamStatus", HttpStatus.SERVICE_UNAVAILABLE.value());
            String upstreamService = extractMissingServiceId(nfe.getMessage());
            if (StringUtils.hasText(upstreamService)) {
                details.put("upstreamService", upstreamService);
            }
            return new ErrorDecision(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    CommonErrorCode.SERVICE_MAINTENANCE.code(),
                    CommonErrorCode.SERVICE_MAINTENANCE.defaultMessage(),
                    details
            );
        }

        if (ex instanceof IllegalArgumentException) {
            status = HttpStatus.BAD_REQUEST;
            error = "invalid_request";
            return new ErrorDecision(status, error, description, details);
        }

        if (ex instanceof WebClientResponseException w) {
            int upstreamStatus = w.getStatusCode().value();
            String upstreamBody = w.getResponseBodyAsString();
            String upstreamMessage = extractUpstreamMessage(upstreamBody);
            String upstreamCode = extractUpstreamCode(upstreamBody);

            // 说明：
            // 识别 boot-cloud-base 的租户域名解析失败（包含“禁用导致查询不到”的场景），返回专用错误码给前端展示。
            if (isTenantResolveBadRequest(w, upstreamBody, upstreamMessage)) {
                details.put("upstreamStatus", upstreamStatus);
                String domain = extractDomain(upstreamBody, w.getMessage());
                if (StringUtils.hasText(domain)) {
                    details.put("domain", domain);
                }
                if (StringUtils.hasText(upstreamMessage)) {
                    details.put("upstreamError", upstreamMessage);
                }
                return new ErrorDecision(
                        HttpStatus.BAD_REQUEST,
                        CommonErrorCode.TENANT_DOMAIN_UNAVAILABLE.code(),
                        CommonErrorCode.TENANT_DOMAIN_UNAVAILABLE.defaultMessage(),
                        details
                );
            }

            if (w.getStatusCode().is4xxClientError()) {
                details.put("upstreamStatus", upstreamStatus);
                if (StringUtils.hasText(upstreamCode)) {
                    details.put("upstreamCode", upstreamCode);
                }
                if (StringUtils.hasText(upstreamMessage)) {
                    description = upstreamMessage;
                }
                if (StringUtils.hasText(upstreamCode)) {
                    HttpStatus mappedStatus = ErrorHttpStatusMapper.resolveByCode(upstreamCode);
                    // 说明：
                    // 上游 4xx 语义优先，防止全部误判为 invalid_request。
                    // 若映射结果是 5xx，说明是目录里的服务级错误码，这里回退 400 以匹配上游当前 4xx 事实。
                    HttpStatus finalStatus = mappedStatus.is5xxServerError() ? HttpStatus.BAD_REQUEST : mappedStatus;
                    String finalDescription = StringUtils.hasText(description) ? description : upstreamCode;
                    if (log.isDebugEnabled()) {
                        log.debug("网关上游4xx错误码透传：upstreamStatus={}, upstreamCode={}, mappedStatus={}, finalStatus={}, message={}",
                                upstreamStatus, upstreamCode, mappedStatus.value(), finalStatus.value(), finalDescription);
                    }
                    return new ErrorDecision(finalStatus, upstreamCode, finalDescription, details);
                }
                return new ErrorDecision(HttpStatus.BAD_REQUEST, CommonErrorCode.INVALID_REQUEST.code(), description, details);
            }
        }

        return new ErrorDecision(status, error, description, details);
    }

    private boolean isTenantResolveBadRequest(
            WebClientResponseException ex,
            String responseBody,
            String upstreamMessage
    ) {
        if (ex.getStatusCode().value() != HttpStatus.BAD_REQUEST.value()) {
            return false;
        }
        String message = ex.getMessage() == null ? "" : ex.getMessage().toLowerCase();
        String body = responseBody == null ? "" : responseBody.toLowerCase();
        String msg = upstreamMessage == null ? "" : upstreamMessage.toLowerCase();
        return message.contains("/internal/tenant/resolve")
                || body.contains("domain not mapped")
                || msg.contains("domain not mapped");
    }

    private String extractUpstreamMessage(String responseBody) {
        if (!StringUtils.hasText(responseBody)) {
            return null;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> root = mapper.readValue(responseBody, Map.class);
            Object direct = root.get("error_description");
            if (direct instanceof String s && StringUtils.hasText(s)) {
                return s.trim();
            }
            Object nestedError = root.get("error");
            if (nestedError instanceof Map<?, ?> errMap) {
                Object nestedMessage = errMap.get("message");
                if (nestedMessage instanceof String s && StringUtils.hasText(s)) {
                    return s.trim();
                }
            }
        } catch (Exception ignore) {
            // 上游未返回 JSON 时忽略解析失败，保持兜底行为。
        }
        return null;
    }

    private String extractUpstreamCode(String responseBody) {
        if (!StringUtils.hasText(responseBody)) {
            return null;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> root = mapper.readValue(responseBody, Map.class);

            Object nestedError = root.get("error");
            if (nestedError instanceof Map<?, ?> errMap) {
                String nestedCode = firstNonBlankText(
                        errMap.get("code"),
                        errMap.get("error_code"),
                        errMap.get("reasonCode")
                );
                if (StringUtils.hasText(nestedCode)) {
                    return CommonErrorCode.canonicalCode(nestedCode);
                }
            }
            if (nestedError instanceof String directError && StringUtils.hasText(directError)) {
                return CommonErrorCode.canonicalCode(directError);
            }

            String directCode = firstNonBlankText(
                    root.get("code"),
                    root.get("error_code"),
                    root.get("reasonCode")
            );
            if (StringUtils.hasText(directCode)) {
                return CommonErrorCode.canonicalCode(directCode);
            }
        } catch (Exception ignore) {
            // 上游未返回 JSON 时忽略解析失败，保持兜底行为。
        }
        return null;
    }

    private static String firstNonBlankText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = String.valueOf(value).trim();
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    private static String extractDomain(String responseBody, String exceptionMessage) {
        String byNotMappedBody = extractByPattern(DOMAIN_NOT_MAPPED_PATTERN, responseBody, 1);
        if (StringUtils.hasText(byNotMappedBody)) {
            return decodeQueryParamValue(byNotMappedBody);
        }
        String byNotMappedMsg = extractByPattern(DOMAIN_NOT_MAPPED_PATTERN, exceptionMessage, 1);
        if (StringUtils.hasText(byNotMappedMsg)) {
            return decodeQueryParamValue(byNotMappedMsg);
        }
        String byQuery = extractByPattern(DOMAIN_QUERY_PATTERN, exceptionMessage, 1);
        if (StringUtils.hasText(byQuery)) {
            return decodeQueryParamValue(byQuery);
        }
        return null;
    }

    private static String extractByPattern(Pattern pattern, String source, int group) {
        if (pattern == null || !StringUtils.hasText(source)) {
            return null;
        }
        Matcher matcher = pattern.matcher(source);
        if (!matcher.find()) {
            return null;
        }
        return matcher.group(group);
    }

    private static String decodeQueryParamValue(String value) {
        if (!StringUtils.hasText(value)) {
            return value;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception ignore) {
            return value;
        }
    }

    private static boolean isMissingServiceInstance(String message) {
        if (!StringUtils.hasText(message)) {
            return false;
        }
        return MISSING_INSTANCE_PATTERN.matcher(message).find();
    }

    private static String extractMissingServiceId(String message) {
        if (!StringUtils.hasText(message)) {
            return null;
        }
        Matcher matcher = MISSING_INSTANCE_PATTERN.matcher(message);
        if (!matcher.find()) {
            return null;
        }
        return matcher.group(1);
    }

    private static boolean isApiPath(String path) {
        return StringUtils.hasText(path) && path.startsWith("/api/");
    }

    private static boolean isOAuthPath(String path) {
        return StringUtils.hasText(path) && path.startsWith("/oauth/");
    }

    private static String safe(String s) {
        if (s == null) return "";
        return s.replace("\"", "'");
    }

    private static class ErrorDecision {
        private final HttpStatus status;
        private final String error;
        private final String description;
        private final Map<String, Object> details;

        private ErrorDecision(HttpStatus status, String error, String description, Map<String, Object> details) {
            this.status = status;
            this.error = error;
            this.description = description;
            this.details = details == null ? Map.of() : details;
        }

        private HttpStatus status() {
            return status;
        }

        private String error() {
            return error;
        }

        private String description() {
            return description;
        }

        private Map<String, Object> details() {
            return details;
        }
    }

    private static class ErrorBody {
        public String error;
        public String errorDescription;
        public String traceId;
    }
}
