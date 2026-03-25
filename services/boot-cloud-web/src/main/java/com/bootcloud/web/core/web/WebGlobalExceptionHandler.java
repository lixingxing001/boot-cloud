package com.bootcloud.web.core.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.AppException;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorHttpStatusMapper;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.web.config.UpstreamProperties;
import com.bootcloud.web.core.util.LogSafeUtil;
import jakarta.servlet.http.HttpServletRequest;
import feign.FeignException;
import feign.RetryableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * boot-cloud-web 全局异常处理，统一为 ApiResponse。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>BFF 层最常见的错误是“调用 boot-cloud-auth 失败/参数校验失败”。</li>
 *   <li>这里统一把异常转换为 ApiResponse，避免前端收到散乱结构。</li>
 * </ul>
 */
@Slf4j
@RestControllerAdvice
public class WebGlobalExceptionHandler {

    private final ObjectMapper objectMapper;
    private final UpstreamProperties upstreamProperties;
    private final ErrorMessageResolver errorMessageResolver;

    public WebGlobalExceptionHandler(
            ObjectMapper objectMapper,
            UpstreamProperties upstreamProperties,
            ErrorMessageResolver errorMessageResolver) {
        this.objectMapper = objectMapper;
        this.upstreamProperties = upstreamProperties;
        this.errorMessageResolver = errorMessageResolver;
    }

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ApiResponse<Void>> handleAppException(HttpServletRequest request, AppException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.getOrCreate();

        String code = CommonErrorCode.BAD_REQUEST.code();
        Object[] args = e.getMessageArgs();
        String message = e.getMessage();
        if (e.getErrorCode() != null) {
            code = e.getErrorCode().code();
            message = errorMessageResolver.resolve(request, e.getErrorCode(), args);
            if (message == null || message.isBlank()) {
                message = e.getMessage();
            }
        } else {
            message = errorMessageResolver.resolveByCode(request, code, message, args);
        }

        Map<String, Object> details = detailsTraceId(traceId);
        if (e.getDetails() != null && !e.getDetails().isEmpty()) {
            details.putAll(e.getDetails());
            details.put("traceId", traceId);
        }

        HttpStatus status = ErrorHttpStatusMapper.resolveByCode(code);
        if (status.is5xxServerError()) {
            log.error("业务异常：path={}, status={}, code={}, msg={}, traceId={}", path, status.value(), code, message, traceId, e);
        } else {
            log.warn("业务异常：path={}, status={}, code={}, msg={}, traceId={}", path, status.value(), code, message, traceId);
        }

        ApiResponse<Void> resp = ApiResponse.error(code, message, details);
        resp.setPath(path);
        return ResponseEntity.status(status).body(resp);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArg(HttpServletRequest request, IllegalArgumentException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("请求参数错误：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String msg = e.getMessage();
        if (msg == null || msg.isBlank()) {
            msg = errorMessageResolver.resolve(request, CommonErrorCode.BAD_REQUEST);
        }
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.BAD_REQUEST.code(), msg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation(HttpServletRequest request, MethodArgumentNotValidException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("参数校验失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String msg = errorMessageResolver.resolve(request, CommonErrorCode.VALIDATION_FAILED);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.VALIDATION_FAILED.code(), msg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
    }

    @ExceptionHandler(HttpStatusCodeException.class)
    public ResponseEntity<ApiResponse<Void>> handleHttpStatus(HttpServletRequest request, HttpStatusCodeException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        HttpStatus status = HttpStatus.resolve(e.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.BAD_GATEWAY;
        }

        String code = "UPSTREAM_ERROR";
        String msg = e.getMessage();

        // 说明：尽量解析 boot-cloud-auth 的 OAuth2 错误格式，给前端更明确的信息
        String raw = e.getResponseBodyAsString();
        if (raw != null && !raw.isBlank()) {
            try {
                JsonNode node = objectMapper.readTree(raw);
                if (node.hasNonNull("error")) {
                    code = node.get("error").asText(code);
                }
                if (node.hasNonNull("error_description")) {
                    msg = node.get("error_description").asText(msg);
                } else if (node.hasNonNull("errorDescription")) {
                    // boot-cloud-auth 统一异常处理使用的是 errorDescription（驼峰），这里做兼容
                    msg = node.get("errorDescription").asText(msg);
                } else if (node.hasNonNull("message")) {
                    msg = node.get("message").asText(msg);
                }
            } catch (Exception ignore) {
                // 解析失败则保持默认信息
            }
        }

        Map<String, Object> upstream = new LinkedHashMap<>();
        upstream.put("status", status.value());
        if (upstreamProperties == null || upstreamProperties.isIncludeBodyInResponseDetails()) {
            upstream.put("bodySnippet", LogSafeUtil.sanitizeAndTruncate(raw,
                    upstreamProperties != null ? upstreamProperties.getMaxBodyCharsForResponseDetails() : 512));
        }

        String publicCode = resolvePublicOauthCode(code, msg);
        String localizedMsg = errorMessageResolver.resolveByCode(request, publicCode, msg);
        if (upstreamProperties != null && upstreamProperties.isDebugLog() && msg != null && !msg.equals(localizedMsg)) {
            upstream.put("message", msg);
        }
        if (StringUtils.hasText(code)) {
            upstream.put("code", code);
        }

        HttpStatus publicStatus = ErrorHttpStatusMapper.resolveByCode(publicCode);
        log.warn("上游调用失败：path={}, upstreamStatus={}, publicStatus={}, upstreamCode={}, publicCode={}, msg={}, localizedMsg={}, traceId={}",
                path, status.value(), publicStatus.value(), code, publicCode, msg, localizedMsg, traceId);
        Map<String, Object> details = buildStrictErrorDetails(traceId, publicCode, msg, upstream, Map.of());
        ApiResponse<Void> resp = ApiResponse.error(publicCode, localizedMsg, details);
        resp.setPath(path);
        return ResponseEntity.status(publicStatus).body(resp);
    }

    @ExceptionHandler(RetryableException.class)
    public ResponseEntity<ApiResponse<Void>> handleFeignRetryable(HttpServletRequest request, RetryableException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("上游连接失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String msg = errorMessageResolver.resolve(request, CommonErrorCode.UPSTREAM_CONNECT_FAILED);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.UPSTREAM_CONNECT_FAILED.code(), msg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(resp);
    }

    @ExceptionHandler(FeignException.class)
    public ResponseEntity<ApiResponse<Void>> handleFeign(HttpServletRequest request, FeignException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();

        int statusCode = e.status();
        HttpStatus status = HttpStatus.resolve(statusCode);
        if (status == null) {
            status = HttpStatus.BAD_GATEWAY;
        }

        String code = "UPSTREAM_ERROR";
        String msg = e.getMessage();

        String raw = e.contentUTF8();
        if (raw != null && !raw.isBlank()) {
            try {
                JsonNode node = objectMapper.readTree(raw);
                if (node.hasNonNull("error")) {
                    code = node.get("error").asText(code);
                }
                if (node.hasNonNull("error_description")) {
                    msg = node.get("error_description").asText(msg);
                } else if (node.hasNonNull("errorDescription")) {
                    msg = node.get("errorDescription").asText(msg);
                } else if (node.hasNonNull("message")) {
                    msg = node.get("message").asText(msg);
                }
            } catch (Exception ignore) {
                // 解析失败则保持默认信息
            }
        }

        Map<String, Object> upstream = new LinkedHashMap<>();
        upstream.put("status", status.value());
        if (upstreamProperties == null || upstreamProperties.isIncludeBodyInResponseDetails()) {
            upstream.put("bodySnippet", LogSafeUtil.sanitizeAndTruncate(raw,
                    upstreamProperties != null ? upstreamProperties.getMaxBodyCharsForResponseDetails() : 512));
        }

        String publicCode = resolvePublicOauthCode(code, msg);
        String localizedMsg = errorMessageResolver.resolveByCode(request, publicCode, msg);
        if (upstreamProperties != null && upstreamProperties.isDebugLog() && msg != null && !msg.equals(localizedMsg)) {
            upstream.put("message", msg);
        }
        if (StringUtils.hasText(code)) {
            upstream.put("code", code);
        }

        HttpStatus publicStatus = ErrorHttpStatusMapper.resolveByCode(publicCode);
        log.warn("上游调用失败：path={}, upstreamStatus={}, publicStatus={}, upstreamCode={}, publicCode={}, msg={}, localizedMsg={}, traceId={}",
                path, status.value(), publicStatus.value(), code, publicCode, msg, localizedMsg, traceId);
        Map<String, Object> details = buildStrictErrorDetails(traceId, publicCode, msg, upstream, Map.of());
        ApiResponse<Void> resp = ApiResponse.error(publicCode, localizedMsg, details);
        resp.setPath(path);
        return ResponseEntity.status(publicStatus).body(resp);
    }

    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceAccess(HttpServletRequest request, ResourceAccessException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("上游连接失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String msg = errorMessageResolver.resolve(request, CommonErrorCode.UPSTREAM_CONNECT_FAILED);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.UPSTREAM_CONNECT_FAILED.code(), msg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(resp);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiResponse<Void>> handleResponseStatus(HttpServletRequest request, ResponseStatusException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.getOrCreate();
        HttpStatus status = HttpStatus.resolve(e.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.BAD_REQUEST;
        }
        String reason = e.getReason() != null ? e.getReason().trim() : "";
        if (!StringUtils.hasText(reason)) {
            reason = status.getReasonPhrase();
        }
        String reasonCode = resolvePublicResponseStatusCode(reason);
        String localizedMsg = errorMessageResolver.resolveByCode(request, reasonCode, reason);
        if (!StringUtils.hasText(localizedMsg)) {
            localizedMsg = errorMessageResolver.resolveByCode(request, CommonErrorCode.INVALID_REQUEST.code(), "请求失败");
        }

        // 说明：透传严格结构 details，避免前端只看到 invalid_request + Request failed。
        Map<String, Object> upstream = new LinkedHashMap<>();
        upstream.put("status", status.value());
        upstream.put("reason", reason);
        upstream.put("exception", "ResponseStatusException");
        Map<String, Object> details = buildStrictErrorDetails(traceId, reasonCode, reason, upstream, Map.of());

        log.warn("请求返回状态异常：path={}, status={}, reason={}, reasonCode={}, localizedMsg={}, traceId={}",
                path, status.value(), reason, reasonCode, localizedMsg, traceId);
        ApiResponse<Void> resp = ApiResponse.error(reasonCode, localizedMsg, details);
        resp.setPath(path);
        return ResponseEntity.status(status).body(resp);
    }

    /**
     * 未定义路由统一返回 404。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>BFF 层对未命中接口返回 api_not_found，便于前端区分链路故障与地址错误。</li>
     *   <li>日志补充 method/path/resourcePath，便于排查反向代理或前端拼接问题。</li>
     * </ul>
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoResourceFound(HttpServletRequest request, NoResourceFoundException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.getOrCreate();
        String msg = errorMessageResolver.resolve(request, CommonErrorCode.API_NOT_FOUND);
        log.warn("BFF 接口未定义：method={}, path={}, resourcePath={}, traceId={}",
                e.getHttpMethod(), path, e.getResourcePath(), traceId);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.API_NOT_FOUND.code(), msg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(resp);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleOther(HttpServletRequest request, Exception e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.error("服务内部错误：path={}, msg={}, traceId={}", path, e.getMessage(), traceId, e);
        String msg = errorMessageResolver.resolve(request, CommonErrorCode.SERVER_ERROR);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.SERVER_ERROR.code(), msg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resp);
    }

    private static Map<String, Object> detailsTraceId(String traceId) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("traceId", traceId);
        return details;
    }

    /**
     * 解析 BFF 对外暴露的 OAuth 业务错误码。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>上游遵循 OAuth2 协议时，主错误码可能固定为 invalid_grant。</li>
     *   <li>细粒度业务原因通常放在 error_description，例如 device_limit_exceeded。</li>
     *   <li>BFF 返回的是业务接口结构，因此优先透出细粒度业务错误码，便于前端做精确提示。</li>
     * </ul>
     */
    private static String resolvePublicOauthCode(String oauthCode, String oauthDescription) {
        if (StringUtils.hasText(oauthDescription) && CommonErrorCode.known(oauthDescription)) {
            return CommonErrorCode.canonicalCode(oauthDescription);
        }
        return StringUtils.hasText(oauthCode) ? oauthCode.trim() : CommonErrorCode.UPSTREAM_ERROR.code();
    }

    /**
     * 解析 ResponseStatusException 对外错误码。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>优先命中公共错误码目录，保证状态码映射与前端分支稳定。</li>
     *   <li>对于自由文本 reason，转换为 lower_snake_case 作为可读业务码。</li>
     * </ul>
     */
    private static String resolvePublicResponseStatusCode(String reason) {
        if (!StringUtils.hasText(reason)) {
            return CommonErrorCode.INVALID_REQUEST.code();
        }
        String normalizedReason = reason.trim();
        if (CommonErrorCode.known(normalizedReason)) {
            return CommonErrorCode.canonicalCode(normalizedReason);
        }

        String lower = normalizedReason.toLowerCase();
        if ("tenant is not allowed".equals(lower)) {
            return CommonErrorCode.TENANT_NOT_ALLOWED.code();
        }
        if ("tenant is disabled".equals(lower)) {
            return CommonErrorCode.TENANT_DISABLED.code();
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
        return CommonErrorCode.canonicalCode(normalizedReason);
    }

    /**
     * 构造严格协议的 error.details。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>根字段固定为 traceId/reasonCode/reasonMessage/upstream/context。</li>
     *   <li>上游原始状态、错误码、原始消息、响应片段都统一落到 upstream 子对象。</li>
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

}
