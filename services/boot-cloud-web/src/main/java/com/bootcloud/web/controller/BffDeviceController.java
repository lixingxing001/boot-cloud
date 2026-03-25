package com.bootcloud.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.starter.config.AuthClientProperties;
import com.bootcloud.auth.starter.util.BasicAuthUtil;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.feign.api.AuthOAuthApi;
import com.bootcloud.web.config.UserAuthProperties;
import com.bootcloud.web.core.util.DeviceIdCookieService;
import com.bootcloud.web.core.util.LogSafeUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 安全设置 BFF：登录设备管理。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>前端只需携带 Authorization Bearer access_token。</li>
 *   <li>boot-cloud-web 代持 client_secret，并调用 boot-cloud-auth 的扩展端点获取设备列表与执行远程登出。</li>
 * </ul>
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class BffDeviceController {

    private static final String TRACE_HEADER = "X-Trace-Id";

    private final AuthOAuthApi authApi;
    private final AuthClientProperties authProps;
    private final ObjectMapper objectMapper;
    private final UserAuthProperties userAuthProperties;
    private final DeviceIdCookieService deviceIdCookieService;

    @GetMapping("/api/web/auth/devices")
    public Map<String, Object> listDevices(HttpServletRequest request, HttpServletResponse response) {
        String tenantId = request.getHeader("X-Tenant-Id");
        String currentDeviceId = getOrCreateUserDeviceId(request, response);

        String accessToken = resolveBearerToken(request);
        if (!StringUtils.hasText(accessToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing access token");
        }

        JsonNode introspect = introspectToken(tenantId, accessToken, request);
        String userId = resolveUserIdFromIntrospect(introspect);
        if (!StringUtils.hasText(userId)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid token");
        }

        Map<String, String> headers = buildAuthHeaders(request);
        String traceId = headers.get(TRACE_HEADER);

        String form = buildFormBody(b -> {
            b.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                b.add("client_secret", authProps.getClientSecret());
            }
            b.add("user_id", userId);
        });

        if (log.isDebugEnabled()) {
            log.debug("BFF 设备列表请求已构造：userId={}, bodyLen={}, traceId={}", userId, form.length(), traceId);
        }

        String raw = authApi.deviceSessionsRaw(headers, form);
        JsonNode parsed = parseJson(raw);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("currentDeviceId", currentDeviceId);
        out.put("sessions", parsed != null && parsed.has("sessions") ? parsed.get("sessions") : objectMapper.createArrayNode());
        out.put("traceId", traceId == null ? "" : traceId);
        return out;
    }

    @PostMapping(value = "/api/web/auth/devices/logout", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> logoutDevice(HttpServletRequest request, HttpServletResponse response, @Valid @RequestBody LogoutDeviceRequest body) {
        String tenantId = request.getHeader("X-Tenant-Id");
        String currentDeviceId = getOrCreateUserDeviceId(request, response);

        String accessToken = resolveBearerToken(request);
        if (!StringUtils.hasText(accessToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing access token");
        }

        JsonNode introspect = introspectToken(tenantId, accessToken, request);
        String userId = resolveUserIdFromIntrospect(introspect);
        if (!StringUtils.hasText(userId)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid token");
        }

        if (StringUtils.hasText(currentDeviceId) && currentDeviceId.equals(body.deviceId)) {
            // 说明：前端若要登出当前设备，推荐直接调用 /api/web/auth/logout（撤销 access/refresh 并清理本地 token）
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot revoke current device via this endpoint");
        }

        Map<String, String> headers = buildAuthHeaders(request);
        String traceId = headers.get(TRACE_HEADER);

        String form = buildFormBody(b -> {
            b.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                b.add("client_secret", authProps.getClientSecret());
            }
            b.add("user_id", userId);
            b.add("device_id", body.deviceId);
        });

        if (log.isInfoEnabled()) {
            log.info("BFF 远程登出设备：tenantId={}, userId={}, deviceId={}, traceId={}",
                    tenantId,
                    userId,
                    maskDeviceId(body.deviceId),
                    traceId);
        }

        String raw = authApi.deviceRevokeRaw(headers, form);
        JsonNode parsed = parseJson(raw);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("result", parsed == null ? objectMapper.nullNode() : parsed);
        out.put("traceId", traceId == null ? "" : traceId);
        return out;
    }

    public static class LogoutDeviceRequest {
        /**
         * 目标设备 deviceId（由服务端生成并写入 HttpOnly Cookie，前端只通过设备列表拿到该值）。
         */
        @NotBlank
        public String deviceId;
    }

    private JsonNode introspectToken(String tenantId, String accessToken, HttpServletRequest request) {
        Map<String, String> headers = buildAuthHeaders(request);
        String traceId = headers.get(TRACE_HEADER);

        String form = buildFormBody(b -> {
            b.add("client_id", authProps.getClientId());
            if (!authProps.isUseBasicAuth()) {
                b.add("client_secret", authProps.getClientSecret());
            }
            b.add("token", accessToken.trim());
        });

        if (log.isDebugEnabled()) {
            log.debug("BFF introspect 请求已构造：tokenLen={}, bodyLen={}, traceId={}", accessToken.length(), form.length(), traceId);
        }
        String raw = authApi.introspectRaw(headers, form);
        JsonNode parsed = parseJson(raw);

        boolean active = parsed != null && parsed.has("active") && parsed.get("active").asBoolean(false);
        if (!active) {
            log.info("BFF introspect 返回 inactive：traceId={}", traceId);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "token inactive");
        }
        return parsed;
    }

    private static String resolveUserIdFromIntrospect(JsonNode introspect) {
        if (introspect == null) return null;
        if (introspect.hasNonNull("sub")) {
            return introspect.get("sub").asText();
        }
        if (introspect.hasNonNull("user_id")) {
            return introspect.get("user_id").asText();
        }
        if (introspect.hasNonNull("userId")) {
            return introspect.get("userId").asText();
        }
        return null;
    }

    private Map<String, String> buildAuthHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);

        String tenantId = request == null ? null : request.getHeader("X-Tenant-Id");
        if (StringUtils.hasText(tenantId)) {
            headers.put("X-Tenant-Id", tenantId.trim());
        }

        String traceId = TraceIdContext.getOrCreate();
        headers.put(TRACE_HEADER, traceId);

        if (authProps != null && authProps.isUseBasicAuth()) {
            headers.put(HttpHeaders.AUTHORIZATION, BasicAuthUtil.basic(authProps.getClientId(), authProps.getClientSecret()));
        }

        // 说明：透传客户端 UA 与 IP，便于 boot-cloud-auth 做设备列表展示与排障
        if (request != null) {
            String ua = request.getHeader("User-Agent");
            String ip = resolveClientIp(request);
            if (StringUtils.hasText(ua)) {
                headers.put("X-Client-User-Agent", sanitizeHeaderValue(ua, 256));
            }
            if (StringUtils.hasText(ip)) {
                headers.put("X-Client-IP", sanitizeHeaderValue(ip, 64));
            }
        }
        return headers;
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
            log.warn("解析 boot-cloud-auth 返回失败（非 JSON）：rawSnippet={}, traceId={}", snippet, traceId);
            return objectMapper.createObjectNode()
                    .put("rawSnippet", snippet)
                    .put("traceId", traceId);
        }
    }

    private String getOrCreateUserDeviceId(HttpServletRequest request, HttpServletResponse response) {
        String cookieName = userAuthProperties != null ? userAuthProperties.getDeviceIdCookieName() : null;
        long maxAgeSeconds = userAuthProperties != null ? userAuthProperties.getDeviceIdCookieMaxAgeSeconds() : 0;
        boolean had = StringUtils.hasText(deviceIdCookieService.readDeviceId(request, cookieName, maxAgeSeconds));
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
        if (!had && log.isDebugEnabled()) {
            log.debug("用户端 deviceId 已生成并写入 cookie：cookieName={}, deviceId={}", cookieName, maskDeviceId(deviceId));
        }
        return deviceId;
    }

    private static String resolveBearerToken(HttpServletRequest request) {
        if (request == null) return null;
        String auth = request.getHeader("Authorization");
        if (!StringUtils.hasText(auth)) return null;
        String v = auth.trim();
        if (!v.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        return v.substring(7).trim();
    }

    private static String buildFormBody(java.util.function.Consumer<FormBodyBuilder> consumer) {
        FormBodyBuilder b = new FormBodyBuilder();
        consumer.accept(b);
        return b.build();
    }

    static final class FormBodyBuilder {
        private final StringBuilder sb = new StringBuilder();

        void add(String key, String value) {
            if (!StringUtils.hasText(key) || value == null) {
                return;
            }
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(URLEncoder.encode(key.trim(), StandardCharsets.UTF_8));
            sb.append("=");
            sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        }

        String build() {
            return sb.toString();
        }
    }

    private static String resolveClientIp(HttpServletRequest request) {
        if (request == null) return "";
        String xff = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xff)) {
            return xff.split(",")[0].trim();
        }
        String xr = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xr)) {
            return xr.trim();
        }
        String ra = request.getRemoteAddr();
        return ra == null ? "" : ra.trim();
    }

    private static String sanitizeHeaderValue(String raw, int maxChars) {
        if (!StringUtils.hasText(raw)) return "";
        String v = raw.trim().replace("\r", "").replace("\n", "");
        if (maxChars <= 0 || v.length() <= maxChars) return v;
        return v.substring(0, maxChars);
    }

    private static String maskDeviceId(String deviceId) {
        if (!StringUtils.hasText(deviceId)) {
            return "";
        }
        String v = deviceId.trim();
        if (v.length() <= 8) {
            return v;
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }
}
