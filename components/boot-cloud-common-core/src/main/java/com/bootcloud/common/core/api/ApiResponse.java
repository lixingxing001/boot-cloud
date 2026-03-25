package com.bootcloud.common.core.api;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.error.ErrorDetailsNormalizer;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 统一 API 响应格式。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>脚手架中的业务接口默认使用 ApiResponse 包装返回值。</li>
 *   <li>统一结构有利于前后端联调、日志排查与错误治理。</li>
 *   <li>注意：OAuth2 标准端点（/oauth/**）保持标准协议格式，不做该包装。</li>
 * </ul>
 */
@Data
public class ApiResponse<T> {

    /**
     * 是否成功。
     */
    private Boolean success;

    /**
     * 成功时的数据载荷。
     */
    private T data;

    /**
     * 失败时的错误信息。
     */
    private ErrorInfo error;

    /**
     * 响应时间。
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;

    /**
     * 请求路径（由服务端自动填充）。
     */
    private String path;

    public ApiResponse() {
        this.timestamp = LocalDateTime.now();
    }

    public static <T> ApiResponse<T> success(T data) {
        ApiResponse<T> resp = new ApiResponse<>();
        resp.success = true;
        resp.data = data;
        return resp;
    }

    public static <T> ApiResponse<T> success(T data, String path) {
        ApiResponse<T> resp = success(data);
        resp.path = path;
        return resp;
    }

    public static <T> ApiResponse<T> error(String code, String message) {
        ApiResponse<T> resp = new ApiResponse<>();
        resp.success = false;
        resp.error = new ErrorInfo(normalizedCode(code), message);
        return resp;
    }

    public static <T> ApiResponse<T> error(String code, String message, String path) {
        ApiResponse<T> resp = error(code, message);
        resp.path = path;
        return resp;
    }

    public static <T> ApiResponse<T> error(String code, String message, Object details) {
        ApiResponse<T> resp = new ApiResponse<>();
        resp.success = false;
        String normalizedCode = normalizedCode(code);
        // 说明：严格统一 error.details 输出结构，不再附加历史兼容字段。
        Object normalizedDetails = ErrorDetailsNormalizer.normalize(details);
        resp.error = new ErrorInfo(normalizedCode, message, normalizedDetails);
        return resp;
    }

    private static String normalizedCode(String rawCode) {
        String normalized = CommonErrorCode.canonicalCode(rawCode);
        if (normalized == null || normalized.isBlank()) {
            return rawCode == null ? "" : rawCode;
        }
        return normalized;
    }

    @Data
    public static class ErrorInfo {
        private String code;
        private String message;
        private Object details;

        public ErrorInfo() {
        }

        public ErrorInfo(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public ErrorInfo(String code, String message, Object details) {
            this.code = code;
            this.message = message;
            this.details = details;
        }
    }
}
