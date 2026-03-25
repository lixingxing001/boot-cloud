package com.bootcloud.common.core.error;

import org.springframework.http.HttpStatus;

/**
 * 错误码到 HTTP 状态码的统一映射。
 */
public final class ErrorHttpStatusMapper {

    private ErrorHttpStatusMapper() {
    }

    public static HttpStatus resolveByCode(String code) {
        String normalized = CommonErrorCode.canonicalCode(code);
        if (normalized == null || normalized.isBlank()) {
            return HttpStatus.BAD_REQUEST;
        }

        if ("unauthorized".equals(normalized)
                || "invalid_token".equals(normalized)
                || "invalid_credentials".equals(normalized)
                || "invalid_client".equals(normalized)
                || "unauthorized_client".equals(normalized)) {
            return HttpStatus.UNAUTHORIZED;
        }

        if ("forbidden".equals(normalized)
                || "access_denied".equals(normalized)
                || "account_disabled".equals(normalized)
                || "tenant_not_allowed".equals(normalized)
                || "tenant_disabled".equals(normalized)) {
            return HttpStatus.FORBIDDEN;
        }

        if ("not_found".equals(normalized)
                || "api_not_found".equals(normalized)
                || "user_not_found".equals(normalized)
                || "tenant_domain_unavailable".equals(normalized)) {
            return HttpStatus.NOT_FOUND;
        }

        if ("duplicate".equals(normalized)
                || "username_exists".equals(normalized)
                || "email_already_registered".equals(normalized)
                || "client_version_too_old".equals(normalized)) {
            return HttpStatus.CONFLICT;
        }

        if ("device_limit_exceeded".equals(normalized)) {
            return HttpStatus.TOO_MANY_REQUESTS;
        }

        if ("upstream_connect_failed".equals(normalized)
                || "upstream_error".equals(normalized)
                || "upstream_unavailable".equals(normalized)) {
            return HttpStatus.BAD_GATEWAY;
        }

        if ("service_unavailable".equals(normalized) || "service_maintenance".equals(normalized)) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }

        if ("server_error".equals(normalized)) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return HttpStatus.BAD_REQUEST;
    }
}
