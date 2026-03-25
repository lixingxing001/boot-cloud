package com.bootcloud.common.core.error;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一业务异常。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>建议业务层抛出 AppException，避免直接拼接中文字符串。</li>
 *   <li>details 用于补充排障字段，最终会落到 ApiResponse.error.details。</li>
 * </ul>
 */
public class AppException extends RuntimeException {

    private final ErrorCode errorCode;
    private final String message;
    private final transient Object[] messageArgs;
    private final Map<String, Object> details;

    public AppException(ErrorCode errorCode) {
        this(errorCode, null, null, null);
    }

    public AppException(ErrorCode errorCode, Throwable cause) {
        this(errorCode, null, null, cause);
    }

    public AppException(ErrorCode errorCode, Map<String, Object> details) {
        this(errorCode, null, details, null);
    }

    public AppException(ErrorCode errorCode, String message) {
        this(errorCode, message, null, null, null);
    }

    public AppException(ErrorCode errorCode, String message, Throwable cause) {
        this(errorCode, message, null, null, cause);
    }

    public AppException(ErrorCode errorCode, String message, Map<String, Object> details) {
        this(errorCode, message, null, details, null);
    }

    public AppException(ErrorCode errorCode, Object[] messageArgs, Map<String, Object> details, Throwable cause) {
        this(errorCode, null, messageArgs, details, cause);
    }

    public AppException(ErrorCode errorCode, String message, Object[] messageArgs, Map<String, Object> details, Throwable cause) {
        super(resolveMessage(errorCode, message), cause);
        this.errorCode = errorCode;
        this.message = resolveMessage(errorCode, message);
        this.messageArgs = messageArgs == null ? new Object[0] : messageArgs.clone();
        this.details = details == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(details));
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public Object[] getMessageArgs() {
        return messageArgs.clone();
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    @Override
    public String getMessage() {
        return message;
    }

    private static String resolveMessage(ErrorCode errorCode, String message) {
        if (message != null && !message.isBlank()) {
            return message;
        }
        return errorCode == null ? null : errorCode.defaultMessage();
    }
}
