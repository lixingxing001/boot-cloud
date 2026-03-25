package com.bootcloud.common.core.error;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 公共错误码目录。
 *
 * <p>这里只保留脚手架级别的通用错误码，避免把具体业务领域常量扩散到基础组件。</p>
 */
public enum CommonErrorCode implements ErrorCode {

    BAD_REQUEST("bad_request", "error.common.bad_request", "请求参数不合法"),
    VALIDATION_FAILED("validation_failed", "error.common.validation_failed", "参数校验失败"),
    NOT_FOUND("not_found", "error.common.not_found", "资源不存在"),
    API_NOT_FOUND("api_not_found", "error.common.api_not_found", "接口不存在"),
    INVALID_REQUEST("invalid_request", "error.common.invalid_request", "请求失败"),
    DUPLICATE("duplicate", "error.common.duplicate", "数据已存在"),
    UNAUTHORIZED("unauthorized", "error.common.unauthorized", "请先登录"),
    FORBIDDEN("forbidden", "error.common.forbidden", "无访问权限"),
    ACCESS_DENIED("access_denied", "error.oauth.access_denied", "访问被拒绝"),
    SERVICE_MAINTENANCE("service_maintenance", "error.common.service_maintenance", "服务维护中，请稍后重试"),
    SERVICE_UNAVAILABLE("service_unavailable", "error.common.service_unavailable", "服务暂不可用"),
    UPSTREAM_ERROR("upstream_error", "error.common.upstream_error", "上游服务调用失败"),
    UPSTREAM_CONNECT_FAILED("upstream_connect_failed", "error.common.upstream_connect_failed", "上游连接失败"),
    SERVER_ERROR("server_error", "error.common.server_error", "服务内部错误"),

    TENANT_DOMAIN_UNAVAILABLE("tenant_domain_unavailable", "error.tenant.domain_unavailable", "租户域名未启用或未映射"),
    TENANT_NOT_ALLOWED("tenant_not_allowed", "error.tenant.not_allowed", "当前租户未被允许访问"),
    TENANT_DISABLED("tenant_disabled", "error.tenant.disabled", "当前租户已禁用"),
    TENANT_HEADER_MISSING("tenant_header_missing", "error.tenant.header_missing", "缺少租户信息"),
    TENANT_HEADER_INVALID("tenant_header_invalid", "error.tenant.header_invalid", "租户信息不合法"),

    CLIENT_VERSION_TOO_OLD("client_version_too_old", "error.client.version_too_old", "客户端版本过旧，请刷新页面"),
    INVALID_CLIENT("invalid_client", "error.oauth.invalid_client", "客户端认证失败"),
    INVALID_GRANT("invalid_grant", "error.oauth.invalid_grant", "凭证无效"),
    INVALID_SCOPE("invalid_scope", "error.oauth.invalid_scope", "授权范围无效"),
    INVALID_TOKEN("invalid_token", "error.oauth.invalid_token", "访问令牌无效"),
    DEVICE_LIMIT_EXCEEDED("device_limit_exceeded", "error.oauth.device_limit_exceeded", "当前账号登录设备数已达上限"),
    OTP_REQUIRED("otp_required", "error.oauth.otp_required", "需要二次验证"),
    INVALID_OTP("invalid_otp", "error.oauth.invalid_otp", "验证码错误或已过期"),
    OTP_INVALID("otp_invalid", "error.oauth.invalid_otp", "验证码错误或已过期"),
    OTP_INVALID_OR_EXPIRED("otp_invalid_or_expired", "error.oauth.invalid_otp", "验证码错误或已过期"),
    BACKUP_CODE_INVALID("backup_code_invalid", "error.oauth.backup_code_invalid", "备份码错误或已失效"),
    INVALID_BACKUP_CODE("invalid_backup_code", "error.oauth.backup_code_invalid", "备份码错误或已失效"),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", "error.oauth.unsupported_grant_type", "授权模式不支持"),
    SERVER_ERROR_OAUTH("server_error", "error.oauth.server_error", "认证服务内部错误"),
    INVALID_REQUEST_OAUTH("invalid_request", "error.oauth.invalid_request", "认证请求无效"),

    USER_NOT_FOUND("user_not_found", "error.user.not_found", "用户不存在"),
    USERNAME_EXISTS("username_exists", "error.user.username_exists", "用户名已存在"),
    EMAIL_ALREADY_REGISTERED("email_already_registered", "error.user.email_already_registered", "邮箱已被注册"),
    INVALID_CREDENTIALS("invalid_credentials", "error.user.invalid_credentials", "用户名或密码错误"),
    ACCOUNT_DISABLED("account_disabled", "error.user.account_disabled", "账户已禁用"),

    PASSWORD_NEW_LENGTH_INVALID("password_new_length_invalid", "error.security.password_new_length_invalid", "新密码长度需要在 8 到 64 之间"),
    PASSWORD_OLD_REQUIRED("password_old_required", "error.security.password_old_required", "旧密码不能为空"),
    PASSWORD_OLD_INCORRECT("password_old_incorrect", "error.security.password_old_incorrect", "旧密码不正确"),
    TOTP_BIND_NOT_INIT("totp_bind_not_init", "error.security.totp_bind_not_init", "请先初始化绑定"),
    TOTP_ALREADY_ENABLED("totp_already_enabled", "error.security.totp_already_enabled", "二次验证已启用"),
    TOTP_NOT_ENABLED("totp_not_enabled", "error.security.totp_not_enabled", "二次验证未启用"),
    TOTP_VERIFY_FAILED("totp_verify_failed", "error.security.totp_verify_failed", "验证码或备份码不正确"),

    IP_BLOCKED("ip_blocked", "error.gateway.ip_blocked", "访问受限"),
    GEO_BLOCKED("geo_blocked", "error.gateway.geo_blocked", "当前地区不可访问");

    private static final Map<String, CommonErrorCode> INDEX = Arrays.stream(values())
            .collect(Collectors.toMap(v -> normalize(v.code), Function.identity(), (a, b) -> a));

    private final String code;
    private final String messageKey;
    private final String defaultMessage;

    CommonErrorCode(String code, String messageKey, String defaultMessage) {
        this.code = code;
        this.messageKey = messageKey;
        this.defaultMessage = defaultMessage;
    }

    @Override
    public String code() {
        return code;
    }

    @Override
    public String messageKey() {
        return messageKey;
    }

    @Override
    public String defaultMessage() {
        return defaultMessage;
    }

    public static CommonErrorCode fromCode(String code) {
        return INDEX.get(normalize(code));
    }

    public static boolean known(String code) {
        return Objects.nonNull(fromCode(code));
    }

    public static String canonicalCode(String rawCode) {
        String code = rawCode == null ? "" : rawCode.trim();
        if (code.isEmpty()) {
            return code;
        }
        if (isNumeric(code)) {
            return code;
        }

        CommonErrorCode mapped = fromCode(code);
        String source = mapped == null ? code : mapped.code();
        return toLowerSnake(source);
    }

    private static String normalize(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isNumeric(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return !value.isEmpty();
    }

    private static String toLowerSnake(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String src = value.trim();
        StringBuilder out = new StringBuilder(src.length() + 8);
        char prev = 0;
        for (int i = 0; i < src.length(); i++) {
            char ch = src.charAt(i);
            char next = (i + 1 < src.length()) ? src.charAt(i + 1) : 0;

            if (ch == '-' || ch == ' ' || ch == '.') {
                appendUnderscoreIfNeeded(out);
                prev = ch;
                continue;
            }
            if (ch == '_') {
                appendUnderscoreIfNeeded(out);
                prev = ch;
                continue;
            }
            boolean upper = Character.isUpperCase(ch);
            boolean prevLowerOrDigit = i > 0 && (Character.isLowerCase(prev) || Character.isDigit(prev));
            boolean nextLower = next != 0 && Character.isLowerCase(next);
            if (upper && (prevLowerOrDigit || (Character.isUpperCase(prev) && nextLower))) {
                appendUnderscoreIfNeeded(out);
            }
            out.append(Character.toLowerCase(ch));
            prev = ch;
        }
        int len = out.length();
        if (len > 0 && out.charAt(len - 1) == '_') {
            out.setLength(len - 1);
        }
        return out.toString();
    }

    private static void appendUnderscoreIfNeeded(StringBuilder out) {
        if (out.length() == 0 || out.charAt(out.length() - 1) == '_') {
            return;
        }
        out.append('_');
    }
}
