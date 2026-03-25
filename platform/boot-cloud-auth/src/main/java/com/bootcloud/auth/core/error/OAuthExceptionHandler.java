package com.bootcloud.auth.core.error;

import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorMessageResolver;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.fasterxml.jackson.annotation.JsonProperty;
import cn.dev33.satoken.exception.SaTokenException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import jakarta.servlet.http.HttpServletRequest;

import jakarta.validation.ConstraintViolationException;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@RestControllerAdvice
public class OAuthExceptionHandler {

    private final ErrorMessageResolver errorMessageResolver;

    public OAuthExceptionHandler(ErrorMessageResolver errorMessageResolver) {
        this.errorMessageResolver = errorMessageResolver;
    }

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<?> handle(HttpServletRequest request, OAuthException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        if (isOAuthPath(path)) {
            OAuthErrorResponse body = new OAuthErrorResponse();
            body.error = e.error();
            body.errorDescription = e.description();
            return ResponseEntity.status(e.httpStatus()).body(body);
        }

        log.warn("业务接口错误：path={}, error={}, desc={}, traceId={}", path, e.error(), e.description(), traceId);
        HttpStatus status = e.httpStatus() == null ? HttpStatus.BAD_REQUEST : e.httpStatus();

        String localizedMsg = errorMessageResolver.resolveByCode(request, e.error(), e.description());
        ApiResponse<Void> resp = ApiResponse.error(e.error(), localizedMsg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(status).body(resp);
    }

    /**
     * Sa-Token OAuth2 异常转为 OAuth2 风格的错误返回（说明：方便网关/前端统一处理）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>Sa-Token OAuth2 内部使用 {@code 301xx} 系列错误码，这里做最小映射。</li>
     *   <li>当前阶段以“可用 + 易排查”为主，后续可根据网关标准进一步细化映射表。</li>
     * </ul>
     */
    @ExceptionHandler(SaTokenException.class)
    public ResponseEntity<?> handleSaToken(HttpServletRequest request, SaTokenException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        int code = e.getCode();

        String error = "invalid_request";
        HttpStatus status = HttpStatus.BAD_REQUEST;

        // 30115/30119/30123: client_secret 校验失败
        if (code == 30115 || code == 30119 || code == 30123) {
            error = "invalid_client";
            status = HttpStatus.UNAUTHORIZED;
        }
        // 30117: 无效 code；30121: 无效 refresh_token
        else if (code == 30117 || code == 30121) {
            error = "invalid_grant";
            status = HttpStatus.BAD_REQUEST;
        }
        // 30112/30116: scope 未签约
        else if (code == 30112 || code == 30116) {
            error = "invalid_scope";
            status = HttpStatus.BAD_REQUEST;
        }

        if (isOAuthPath(path)) {
            OAuthErrorResponse body = new OAuthErrorResponse();
            body.error = error;
            body.errorDescription = e.getMessage();
            return ResponseEntity.status(status).body(body);
        }

        log.warn("业务接口 Sa-Token 异常：path={}, code={}, msg={}, traceId={}", path, code, e.getMessage(), traceId);
        String localizedMsg = errorMessageResolver.resolveByCode(request, error, e.getMessage());
        ApiResponse<Void> resp = ApiResponse.error(error, localizedMsg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(status).body(resp);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidation(HttpServletRequest request, MethodArgumentNotValidException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        if (isOAuthPath(path)) {
            OAuthErrorResponse body = new OAuthErrorResponse();
            body.error = "invalid_request";
            body.errorDescription = "validation failed";
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
        }
        log.warn("参数校验失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.VALIDATION_FAILED);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.VALIDATION_FAILED.code(), localizedMsg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> handleConstraint(HttpServletRequest request, ConstraintViolationException e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        if (isOAuthPath(path)) {
            OAuthErrorResponse body = new OAuthErrorResponse();
            body.error = "invalid_request";
            body.errorDescription = "validation failed";
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
        }
        log.warn("参数校验失败：path={}, msg={}, traceId={}", path, e.getMessage(), traceId);
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.VALIDATION_FAILED);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.VALIDATION_FAILED.code(), localizedMsg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleOther(HttpServletRequest request, Exception e) {
        String path = request.getRequestURI();
        String traceId = TraceIdContext.get();
        if (isOAuthPath(path)) {
            // 说明：
            // 1) /oauth/** 过去只返回统一的 server_error，但不打印异常栈，排查成本高。
            // 2) 这里补充 error 日志，用于在 boot-cloud-auth 控制台直接定位根因。
            // 3) 注意安全：不输出 password、client_secret、token 等敏感字段，只输出白名单参数与无 message 的堆栈摘要。
            logOAuthInternalError(request, traceId, e);
            OAuthErrorResponse body = new OAuthErrorResponse();
            body.error = "server_error";
            body.errorDescription = "internal error";
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
        }
        log.error("服务内部错误：path={}, msg={}, traceId={}", path, e.getMessage(), traceId, e);
        String localizedMsg = errorMessageResolver.resolve(request, CommonErrorCode.SERVER_ERROR);
        ApiResponse<Void> resp = ApiResponse.error(CommonErrorCode.SERVER_ERROR.code(), localizedMsg, detailsTraceId(traceId));
        resp.setPath(path);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resp);
    }

    private static void logOAuthInternalError(HttpServletRequest request, String traceId, Exception e) {
        String method = request == null ? null : request.getMethod();
        String path = request == null ? null : request.getRequestURI();
        String tenantId = safeHeader(request, "X-Tenant-Id");

        // 仅输出白名单参数，避免把 password/client_secret 等敏感信息写入日志。
        Map<String, Object> safeParams = safeOAuthParams(request);

        // 为了避免把异常 message 里的敏感内容写进日志，这里输出“无 message 的堆栈摘要”。
        // 说明：堆栈摘要依然足够用于定位到具体代码行。
        String stack = formatThrowableWithoutMessage(e, 10, 6);
        String errType = e == null ? null : e.getClass().getName();

        log.error("OAuth 服务内部错误：method={}, path={}, tenantId={}, params={}, traceId={}, errType={}, stack={}",
                method, path, tenantId, safeParams, traceId, errType, stack);
    }

    private static String safeHeader(HttpServletRequest request, String name) {
        if (request == null || name == null || name.isBlank()) {
            return null;
        }
        try {
            String v = request.getHeader(name);
            if (v == null) {
                return null;
            }
            String s = v.trim();
            return s.isEmpty() ? null : truncate(s, 64);
        } catch (Exception ex) {
            return null;
        }
    }

    private static Map<String, Object> safeOAuthParams(HttpServletRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (request == null) {
            return out;
        }

        // 说明：
        // 这里维护一个参数白名单，只记录定位问题所需的字段。
        // 强制不记录：password、client_secret、refresh_token、code、signature 等敏感参数。
        Set<String> allow = Set.of(
                "grant_type",
                "client_id",
                "scope",
                "username",
                "device_id",
                "redirect_uri",
                "provider",
                "subject_token_type"
        );
        for (String k : allow) {
            try {
                String v = request.getParameter(k);
                if (v == null || v.isBlank()) {
                    continue;
                }
                out.put(k, truncate(v.trim(), 256));
            } catch (Exception ex) {
                // ignore
            }
        }
        return out;
    }

    /**
     * 输出 Throwable 的“无 message 堆栈摘要”，避免把敏感信息写进日志。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>只打印异常类型与部分栈帧。</li>
     *   <li>最多输出若干层 cause，避免日志过长。</li>
     * </ul>
     */
    private static String formatThrowableWithoutMessage(Throwable t, int maxFramesRoot, int maxFramesCause) {
        if (t == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        Throwable cur = t;
        int depth = 0;
        while (cur != null && depth < 6) {
            if (depth == 0) {
                sb.append(cur.getClass().getName());
            } else {
                sb.append(" | causedBy=").append(cur.getClass().getName());
            }

            int maxFrames = depth == 0 ? maxFramesRoot : maxFramesCause;
            StackTraceElement[] st = cur.getStackTrace();
            if (st != null && st.length > 0) {
                int n = Math.min(st.length, Math.max(maxFrames, 1));
                sb.append(" | frames=").append(n).append("/");
                sb.append(st.length);
                sb.append(" ");
                for (int i = 0; i < n; i++) {
                    StackTraceElement f = st[i];
                    sb.append("at ");
                    sb.append(f.getClassName()).append(".").append(f.getMethodName());
                    sb.append("(").append(f.getFileName()).append(":").append(f.getLineNumber()).append(")");
                    if (i < n - 1) {
                        sb.append("; ");
                    }
                }
            }
            cur = cur.getCause();
            depth++;
        }
        return truncate(sb.toString(), 4000);
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        int m = Math.max(max, 1);
        if (s.length() <= m) {
            return s;
        }
        return s.substring(0, m);
    }

    private static boolean isOAuthPath(String path) {
        return path != null && path.startsWith("/oauth/");
    }

    private static Map<String, Object> detailsTraceId(String traceId) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("traceId", traceId);
        return details;
    }

    @Data
    public static class OAuthErrorResponse {
        private String error;
        @JsonProperty("error_description")
        private String errorDescription;
    }
}
