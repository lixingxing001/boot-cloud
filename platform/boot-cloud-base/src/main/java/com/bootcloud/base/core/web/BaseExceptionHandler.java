package com.bootcloud.base.core.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import com.bootcloud.common.core.trace.TraceIdContext;
import jakarta.validation.ConstraintViolationException;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * boot-cloud-base 统一异常返回。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>保持与网关/auth 类似的 error 结构，便于排查。</li>
 *   <li>该服务主要用于内部调用与管理接口；返回尽量明确但不泄露敏感信息。</li>
 * </ul>
 */
@RestControllerAdvice
public class BaseExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(BaseExceptionHandler.class);
    private final ErrorMessageResolver errorMessageResolver;

    public BaseExceptionHandler(ErrorMessageResolver errorMessageResolver) {
        this.errorMessageResolver = errorMessageResolver;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleIllegalArgument(HttpServletRequest request, IllegalArgumentException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("请求参数错误：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String localizedMsg = (e.getMessage() == null || e.getMessage().isBlank())
                ? errorMessageResolver.resolve(request, CommonErrorCode.BAD_REQUEST)
                : e.getMessage();
        if (isAdminPath(path)) {
            ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.BAD_REQUEST.code(), localizedMsg, detailsTraceId(traceId));
            resp.setPath(path);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.of("invalid_request", localizedMsg));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> handleConstraint(HttpServletRequest request, ConstraintViolationException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("参数校验失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.VALIDATION_FAILED);
        if (isAdminPath(path)) {
            ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.VALIDATION_FAILED.code(), localizedMsg, detailsTraceId(traceId));
            resp.setPath(path);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.of("invalid_request", localizedMsg));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleMethodArgNotValid(HttpServletRequest request, MethodArgumentNotValidException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.warn("参数校验失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.VALIDATION_FAILED);
        if (isAdminPath(path)) {
            ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.VALIDATION_FAILED.code(), localizedMsg, detailsTraceId(traceId));
            resp.setPath(path);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.of("invalid_request", localizedMsg));
    }

    /**
     * 未定义路由统一返回 404。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>内部管理路径维持 ApiResponse 结构，方便后台统一处理。</li>
     *   <li>非管理路径沿用 OAuth 风格 error 字段，避免打破历史调用兼容性。</li>
     * </ul>
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<?> handleNoResourceFound(HttpServletRequest request, NoResourceFoundException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.getOrCreate();
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.API_NOT_FOUND);
        log.warn("base 接口未定义：method={}, path={}, resourcePath={}, traceId={}",
                e.getHttpMethod(), path, e.getResourcePath(), traceId);
        if (isAdminPath(path)) {
            ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.API_NOT_FOUND.code(), localizedMsg, detailsTraceId(traceId));
            resp.setPath(path);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(resp);
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ErrorResponse.of(CommonErrorCode.API_NOT_FOUND.code(), localizedMsg));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleOther(HttpServletRequest request, Exception e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        log.error("服务内部错误：path={}, msg={}, traceId={}", path, e.getMessage(), traceId, e);
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.SERVER_ERROR);
        if (isAdminPath(path)) {
            ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.SERVER_ERROR.code(), localizedMsg, detailsTraceId(traceId));
            resp.setPath(path);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resp);
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ErrorResponse.of("server_error", localizedMsg));
    }

    private static boolean isAdminPath(String path) {
        return path != null && path.startsWith("/internal/admin/");
    }

    private static Map<String, Object> detailsTraceId(String traceId) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("traceId", traceId);
        return details;
    }

    @Data
    public static class ErrorResponse {
        private String error;
        @JsonProperty("error_description")
        private String errorDescription;

        public static ErrorResponse of(String error, String desc) {
            ErrorResponse r = new ErrorResponse();
            r.error = error;
            r.errorDescription = desc;
            return r;
        }
    }
}

