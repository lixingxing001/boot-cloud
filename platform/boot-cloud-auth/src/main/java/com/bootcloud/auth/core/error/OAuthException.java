package com.bootcloud.auth.core.error;

import org.springframework.http.HttpStatus;

public class OAuthException extends RuntimeException {

    private final String error;
    private final String description;
    private final HttpStatus httpStatus;

    public OAuthException(String error, String description, HttpStatus httpStatus) {
        super(description);
        this.error = error;
        this.description = description;
        this.httpStatus = httpStatus;
    }

    public String error() {
        return error;
    }

    public String description() {
        return description;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }

    public static OAuthException invalidRequest(String desc) {
        return new OAuthException("invalid_request", desc, HttpStatus.BAD_REQUEST);
    }

    public static OAuthException invalidClient(String desc) {
        return new OAuthException("invalid_client", desc, HttpStatus.UNAUTHORIZED);
    }

    public static OAuthException unauthorizedClient(String desc) {
        return new OAuthException("unauthorized_client", desc, HttpStatus.FORBIDDEN);
    }

    public static OAuthException invalidGrant(String desc) {
        return new OAuthException("invalid_grant", desc, HttpStatus.BAD_REQUEST);
    }

    public static OAuthException unsupportedGrantType(String desc) {
        return new OAuthException("unsupported_grant_type", desc, HttpStatus.BAD_REQUEST);
    }

    public static OAuthException unsupportedResponseType(String desc) {
        return new OAuthException("unsupported_response_type", desc, HttpStatus.BAD_REQUEST);
    }

    public static OAuthException invalidScope(String desc) {
        return new OAuthException("invalid_scope", desc, HttpStatus.BAD_REQUEST);
    }

    public static OAuthException serverError(String desc) {
        return new OAuthException("server_error", desc, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

