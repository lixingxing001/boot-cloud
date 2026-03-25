package com.bootcloud.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.starter.config.AuthClientProperties;
import com.bootcloud.auth.starter.util.BasicAuthUtil;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.feign.api.AuthOAuthApi;
import com.bootcloud.web.config.UserAuthProperties;
import com.bootcloud.web.core.tenant.WebRuntimeTenantResolver;
import com.bootcloud.web.core.util.DeviceIdCookieService;
import com.bootcloud.web.core.util.LogSafeUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 通用认证 BFF。
 *
 * <p>职责非常明确：</p>
 * <ul>
 *   <li>前端只提交账号、口令、授权码和刷新令牌。</li>
 *   <li>BFF 在服务端代持 OAuth Client 信息并转发到认证中心。</li>
 *   <li>所有请求统一补齐租户头、设备标识和 TraceId。</li>
 * </ul>
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class BffAuthController {

    private static final String TRACE_HEADER = "X-Trace-Id";

    private final AuthOAuthApi authApi;
    private final AuthClientProperties authProps;
    private final ObjectMapper objectMapper;
    private final UserAuthProperties userAuthProperties;
    private final DeviceIdCookieService deviceIdCookieService;
    private final WebRuntimeTenantResolver webRuntimeTenantResolver;

    /**
     * 用户名密码换取访问令牌。
     */
    @PostMapping(value = "/api/web/auth/password/token", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode passwordToken(
            HttpServletRequest request,
            HttpServletResponse response,
            @Valid @RequestBody PasswordTokenRequest body
    ) {
        String tenantId = webRuntimeTenantResolver.resolveTenantId(request, "bff_password_token");
        String deviceId = getOrCreateUserDeviceId(request, response);
        Map<String, String> headers = buildAuthHeaders(request, tenantId);

        String form = buildFormBody(builder -> {
            builder.add("grant_type", "password");
            builder.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                builder.add("client_secret", authProps.getClientSecret());
            }
            builder.add("username", body.username);
            builder.add("password", body.password);
            builder.add("scope", body.scope);
            builder.add("otp", body.otp);
            builder.add("backup_code", body.backupCode);
            builder.add("device_id", deviceId);
        });

        log.info("BFF 密码登录：tenantId={}, username={}, deviceId={}, traceId={}",
                tenantId,
                safe(body.username),
                maskDeviceId(deviceId),
                headers.get(TRACE_HEADER));
        return parseJson(callTokenRaw(headers, form));
    }

    /**
     * 刷新访问令牌。
     */
    @PostMapping(value = "/api/web/auth/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode refresh(
            HttpServletRequest request,
            HttpServletResponse response,
            @Valid @RequestBody RefreshTokenRequest body
    ) {
        String tenantId = webRuntimeTenantResolver.resolveTenantId(request, "bff_refresh_token");
        String deviceId = getOrCreateUserDeviceId(request, response);
        Map<String, String> headers = buildAuthHeaders(request, tenantId);

        String form = buildFormBody(builder -> {
            builder.add("grant_type", "refresh_token");
            builder.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                builder.add("client_secret", authProps.getClientSecret());
            }
            builder.add("refresh_token", body.refreshToken);
            builder.add("device_id", deviceId);
        });

        log.debug("BFF 刷新令牌：tenantId={}, deviceId={}, traceId={}",
                tenantId,
                maskDeviceId(deviceId),
                headers.get(TRACE_HEADER));
        return parseJson(callTokenRaw(headers, form));
    }

    /**
     * 授权码换取访问令牌。
     */
    @PostMapping(value = "/api/web/auth/oauth/token", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode exchangeAuthorizationCode(
            HttpServletRequest request,
            HttpServletResponse response,
            @Valid @RequestBody AuthorizationCodeTokenRequest body
    ) {
        String tenantId = webRuntimeTenantResolver.resolveTenantId(request, "bff_authorization_code_token");
        String deviceId = getOrCreateUserDeviceId(request, response);
        Map<String, String> headers = buildAuthHeaders(request, tenantId);

        String form = buildFormBody(builder -> {
            builder.add("grant_type", "authorization_code");
            builder.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                builder.add("client_secret", authProps.getClientSecret());
            }
            builder.add("code", body.code);
            builder.add("redirect_uri", body.redirectUri);
            builder.add("code_verifier", body.codeVerifier);
            builder.add("device_id", deviceId);
        });

        log.info("BFF 授权码换令牌：tenantId={}, code={}, deviceId={}, traceId={}",
                tenantId,
                mask(body.code),
                maskDeviceId(deviceId),
                headers.get(TRACE_HEADER));
        return parseJson(callTokenRaw(headers, form));
    }

    /**
     * 当前设备登出。
     */
    @PostMapping(value = "/api/web/auth/logout", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode logout(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestBody(required = false) LogoutRequest body
    ) {
        String tenantId = webRuntimeTenantResolver.resolveTenantId(request, "bff_logout");
        String deviceId = getOrCreateUserDeviceId(request, response);
        Map<String, String> headers = buildAuthHeaders(request, tenantId);
        String accessToken = resolveBearerToken(request);
        String refreshToken = body == null ? null : body.refreshToken;

        log.info("BFF 用户登出：tenantId={}, hasAccessToken={}, refreshTokenLen={}, deviceId={}, traceId={}",
                tenantId,
                StringUtils.hasText(accessToken),
                refreshToken == null ? 0 : refreshToken.length(),
                maskDeviceId(deviceId),
                headers.get(TRACE_HEADER));

        JsonNode accessResult = revokeIfPresent(headers, accessToken, "access_token", deviceId);
        JsonNode refreshResult = revokeIfPresent(headers, refreshToken, "refresh_token", deviceId);

        var out = objectMapper.createObjectNode();
        out.set("access", accessResult == null ? objectMapper.nullNode() : accessResult);
        out.set("refresh", refreshResult == null ? objectMapper.nullNode() : refreshResult);
        out.put("traceId", headers.getOrDefault(TRACE_HEADER, ""));
        return out;
    }

    public static class PasswordTokenRequest {
        /** 登录账号。 */
        @NotBlank
        public String username;
        /** 登录口令。 */
        @NotBlank
        public String password;
        /** 可选申请范围。 */
        public String scope;
        /** 可选 TOTP 验证码。 */
        public String otp;
        /** 可选 MFA 备份码。 */
        public String backupCode;
    }

    public static class RefreshTokenRequest {
        /** 刷新令牌。 */
        @NotBlank
        public String refreshToken;
    }

    public static class LogoutRequest {
        /** 刷新令牌，推荐前端一并提交以便完整撤销。 */
        public String refreshToken;
    }

    public static class AuthorizationCodeTokenRequest {
        /** 授权码。 */
        @NotBlank
        public String code;
        /** 可选回调地址。 */
        public String redirectUri;
        /** PKCE 校验值。 */
        public String codeVerifier;
    }

    private String getOrCreateUserDeviceId(HttpServletRequest request, HttpServletResponse response) {
        String cookieName = userAuthProperties != null ? userAuthProperties.getDeviceIdCookieName() : null;
        long maxAgeSeconds = userAuthProperties != null ? userAuthProperties.getDeviceIdCookieMaxAgeSeconds() : 0L;
        boolean hadDeviceId = StringUtils.hasText(deviceIdCookieService.readDeviceId(request, cookieName, maxAgeSeconds));
        String deviceId = deviceIdCookieService.getOrCreateDeviceId(
                request,
                response,
                cookieName,
                maxAgeSeconds,
                userAuthProperties != null ? userAuthProperties.getDeviceIdCookiePath() : "/",
                userAuthProperties != null ? userAuthProperties.getDeviceIdCookieSameSite() : "Lax",
                userAuthProperties != null && userAuthProperties.isDeviceIdCookieSecure(),
                userAuthProperties != null ? userAuthProperties.getDeviceIdCookieDomain() : null
        );
        if (!hadDeviceId && log.isDebugEnabled()) {
            log.debug("BFF 已写入新的设备标识 Cookie：cookieName={}, deviceId={}", cookieName, maskDeviceId(deviceId));
        }
        return deviceId;
    }

    private JsonNode parseJson(String raw) {
        try {
            if (!StringUtils.hasText(raw)) {
                return objectMapper.nullNode();
            }
            return objectMapper.readTree(raw);
        } catch (Exception e) {
            String traceId = TraceIdContext.get();
            String snippet = LogSafeUtil.sanitizeAndTruncate(raw, 512);
            log.warn("BFF 解析认证中心返回失败：rawSnippet={}, traceId={}", snippet, traceId);
            return objectMapper.createObjectNode()
                    .put("rawSnippet", snippet)
                    .put("traceId", traceId == null ? "" : traceId);
        }
    }

    private Map<String, String> buildAuthHeaders(HttpServletRequest request, String tenantId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        if (StringUtils.hasText(tenantId)) {
            headers.put("X-Tenant-Id", tenantId.trim());
        }

        String traceId = TraceIdContext.getOrCreate();
        headers.put(TRACE_HEADER, traceId);

        if (authProps != null && authProps.isUseBasicAuth()) {
            headers.put("Authorization", BasicAuthUtil.basic(authProps.getClientId(), authProps.getClientSecret()));
        }

        if (request != null) {
            String userAgent = request.getHeader("User-Agent");
            String clientIp = resolveClientIp(request);
            String acceptLanguage = request.getHeader("Accept-Language");
            if (StringUtils.hasText(userAgent)) {
                headers.put("X-Client-User-Agent", sanitizeHeaderValue(userAgent, 256));
            }
            if (StringUtils.hasText(clientIp)) {
                headers.put("X-Client-IP", sanitizeHeaderValue(clientIp, 64));
            }
            if (StringUtils.hasText(acceptLanguage)) {
                headers.put("Accept-Language", sanitizeHeaderValue(acceptLanguage, 128));
            }
        }
        return headers;
    }

    private String callTokenRaw(Map<String, String> headers, String form) {
        try {
            return authApi.tokenRaw(headers, form);
        } catch (feign.FeignException e) {
            String traceId = TraceIdContext.get();
            String raw = e.contentUTF8();
            String snippet = LogSafeUtil.sanitizeAndTruncate(raw, 512);
            log.warn("BFF 调用 /oauth/token 失败：status={}, rawSnippet={}, traceId={}", e.status(), snippet, traceId);
            if (StringUtils.hasText(raw)) {
                return raw;
            }
            return objectMapper.createObjectNode()
                    .put("error", "upstream_unavailable")
                    .put("error_description", "boot-cloud-auth unreachable or timeout")
                    .put("status", e.status())
                    .put("traceId", traceId == null ? "" : traceId)
                    .toString();
        } catch (Exception e) {
            String traceId = TraceIdContext.get();
            log.warn("BFF 调用 /oauth/token 连接失败：msg={}, traceId={}", e.getMessage(), traceId);
            return objectMapper.createObjectNode()
                    .put("error", "upstream_unavailable")
                    .put("error_description", "boot-cloud-auth unreachable")
                    .put("traceId", traceId == null ? "" : traceId)
                    .toString();
        }
    }

    private String callRevokeRaw(Map<String, String> headers, String form) {
        try {
            return authApi.revokeRaw(headers, form);
        } catch (feign.FeignException e) {
            String traceId = TraceIdContext.get();
            String raw = e.contentUTF8();
            String snippet = LogSafeUtil.sanitizeAndTruncate(raw, 512);
            log.warn("BFF 调用 /oauth/revoke 失败：status={}, rawSnippet={}, traceId={}", e.status(), snippet, traceId);
            return raw;
        } catch (Exception e) {
            String traceId = TraceIdContext.get();
            log.warn("BFF 调用 /oauth/revoke 连接失败：msg={}, traceId={}", e.getMessage(), traceId);
            return objectMapper.createObjectNode()
                    .put("error", "upstream_unavailable")
                    .put("error_description", "boot-cloud-auth unreachable")
                    .put("traceId", traceId == null ? "" : traceId)
                    .toString();
        }
    }

    private JsonNode revokeIfPresent(Map<String, String> headers, String token, String tokenTypeHint, String deviceId) {
        if (!StringUtils.hasText(token)) {
            return objectMapper.createObjectNode()
                    .put("attempted", false)
                    .put("revoked", false);
        }
        String form = buildFormBody(builder -> {
            builder.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                builder.add("client_secret", authProps.getClientSecret());
            }
            builder.add("token", token.trim());
            builder.add("token_type_hint", tokenTypeHint);
            builder.add("device_id", deviceId);
        });
        JsonNode parsed = parseJson(callRevokeRaw(headers, form));
        boolean revoked = parsed != null && parsed.path("revoked").asBoolean(false);
        if (!revoked && log.isDebugEnabled()) {
            log.debug("BFF 撤销令牌失败：tokenTypeHint={}, token={}, deviceId={}",
                    tokenTypeHint,
                    mask(token),
                    maskDeviceId(deviceId));
        }
        var out = objectMapper.createObjectNode();
        out.put("attempted", true);
        out.put("revoked", revoked);
        out.set("raw", parsed == null ? objectMapper.nullNode() : parsed);
        return out;
    }

    private static String resolveBearerToken(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String auth = request.getHeader("Authorization");
        if (!StringUtils.hasText(auth)) {
            return null;
        }
        String value = auth.trim();
        if (!value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = value.substring(7).trim();
        return StringUtils.hasText(token) ? token : null;
    }

    private static String resolveClientIp(HttpServletRequest request) {
        if (request == null) {
            return "";
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(realIp)) {
            return realIp.trim();
        }
        String remoteAddr = request.getRemoteAddr();
        return remoteAddr == null ? "" : remoteAddr.trim();
    }

    private static String sanitizeHeaderValue(String raw, int maxChars) {
        if (!StringUtils.hasText(raw)) {
            return "";
        }
        String value = raw.trim().replace("\r", "").replace("\n", "");
        return value.length() <= maxChars ? value : value.substring(0, maxChars);
    }

    private static String buildFormBody(java.util.function.Consumer<FormBodyBuilder> consumer) {
        FormBodyBuilder builder = new FormBodyBuilder();
        consumer.accept(builder);
        return builder.build();
    }

    private static String mask(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 10) {
            return "****";
        }
        return trimmed.substring(0, 4) + "****" + trimmed.substring(trimmed.length() - 4);
    }

    private static String maskDeviceId(String deviceId) {
        if (!StringUtils.hasText(deviceId)) {
            return "";
        }
        String value = deviceId.trim();
        if (value.length() <= 8) {
            return value;
        }
        return value.substring(0, 4) + "****" + value.substring(value.length() - 4);
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    static final class FormBodyBuilder {
        private final StringBuilder builder = new StringBuilder();

        void add(String key, String value) {
            if (!StringUtils.hasText(key) || value == null) {
                return;
            }
            if (builder.length() > 0) {
                builder.append('&');
            }
            builder.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            builder.append('=');
            builder.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        }

        String build() {
            return builder.toString();
        }
    }
}
