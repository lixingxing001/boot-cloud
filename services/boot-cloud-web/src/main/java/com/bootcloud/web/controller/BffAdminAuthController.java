package com.bootcloud.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.web.config.AdminAuthProperties;
import com.bootcloud.web.core.admin.AdminTokenService;
import com.bootcloud.web.core.util.DeviceIdCookieService;
import com.bootcloud.web.core.util.LogSafeUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 后台管理端 BFF 登录接口（boot-cloud-web -> boot-cloud-auth）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该接口给“后台浏览器前端”使用：前端只传用户名/密码，不传 OAuth2 client_secret。</li>
 *   <li>boot-cloud-web 在服务端代持后台专用 client（boot.cloud.web.admin-auth.*），调用 boot-cloud-auth 的 admin_password grant。</li>
 *   <li>拿到的 access_token 用于调用网关：/api/admin/**（管理端服务 已作为 OAuth2 资源服务校验 Bearer token）。</li>
 * </ul>
 */
@Slf4j
@RestController
public class BffAdminAuthController {

    private final AdminTokenService adminTokenService;
    private final ObjectMapper objectMapper;
    private final AdminAuthProperties adminAuthProperties;
    private final DeviceIdCookieService deviceIdCookieService;

    public BffAdminAuthController(
            AdminTokenService adminTokenService,
            ObjectMapper objectMapper,
            AdminAuthProperties adminAuthProperties,
            DeviceIdCookieService deviceIdCookieService
    ) {
        this.adminTokenService = adminTokenService;
        this.objectMapper = objectMapper;
        this.adminAuthProperties = adminAuthProperties;
        this.deviceIdCookieService = deviceIdCookieService;
    }

    /**
     * 后台方向（BFF）：账号密码登录（admin_password -> token）。
     */
    @PostMapping(value = "/api/web/admin/auth/password/token", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode adminPasswordToken(HttpServletRequest request, HttpServletResponse response, @Valid @RequestBody AdminPasswordTokenRequest body) {
        String tenantId = request.getHeader("X-Tenant-Id");
        String deviceId = getOrCreateDeviceId(request, response);

        // 说明：
        // 这里打印“入口请求头 traceId”和“MDC traceId”，用于快速判断 traceId 丢失发生在哪一跳：
        // 1) headerTraceId 为空：说明网关 -> boot-cloud-web 的透传就已经丢失
        // 2) headerTraceId 有值但 mdcTraceId 为空：说明 TraceIdServletFilter 没有生效或未启用
        // 3) 两者都有值但不一致：说明链路中存在覆盖或生成新 traceId 的逻辑，需要进一步排查
        String headerTraceId = request.getHeader("X-Trace-Id");
        String mdcTraceId = TraceIdContext.get();
        log.info("收到后台登录请求：tenantId={}, username={}, deviceId={}, headerTraceId={}, mdcTraceId={}",
                tenantId, body.username, maskDeviceId(deviceId), headerTraceId, mdcTraceId);

        String raw = adminTokenService.passwordToken(tenantId, body.username, body.password, deviceId).getBody();
        return parseJson(raw);
    }

    /**
     * 后台方向（BFF）：刷新 token（refresh_token -> token）。
     */
    @PostMapping(value = "/api/web/admin/auth/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode adminRefresh(HttpServletRequest request, HttpServletResponse response, @Valid @RequestBody AdminRefreshTokenRequest body) {
        String tenantId = request.getHeader("X-Tenant-Id");
        String deviceId = getOrCreateDeviceId(request, response);

        String headerTraceId = request.getHeader("X-Trace-Id");
        String mdcTraceId = TraceIdContext.get();
        log.debug("收到后台 refresh 请求：tenantId={}, deviceId={}, headerTraceId={}, mdcTraceId={}",
                tenantId, maskDeviceId(deviceId), headerTraceId, mdcTraceId);

        String raw = adminTokenService.refreshToken(tenantId, body.refreshToken, deviceId).getBody();
        return parseJson(raw);
    }

    public static class AdminPasswordTokenRequest {
        @NotBlank
        public String username;
        @NotBlank
        public String password;
    }

    public static class AdminRefreshTokenRequest {
        @NotBlank
        public String refreshToken;
    }

    public static class AdminLogoutRequest {
        public String refreshToken;
    }

    /**
     * 后台方向（BFF）：登出（服务端真实撤销 token）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>同时撤销 access_token 与 refresh_token。</li>
     *   <li>只登出当前设备：使用后台 HttpOnly deviceId cookie 透传 device_id。</li>
     * </ul>
     */
    @PostMapping(value = "/api/web/admin/auth/logout", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode adminLogout(HttpServletRequest request, HttpServletResponse response, @RequestBody AdminLogoutRequest body) {
        String tenantId = request.getHeader("X-Tenant-Id");

        String cookieName = adminAuthProperties.getDeviceIdCookieName();
        String deviceId = deviceIdCookieService.readDeviceId(
                request,
                cookieName,
                adminAuthProperties.getDeviceIdCookieMaxAgeSeconds()
        );
        if (!StringUtils.hasText(deviceId)) {
            // 说明：登出时不强制生成新 cookie，避免写入与当前会话无关的 deviceId。
            log.debug("后台登出：deviceId cookie 缺失或校验失败，cookieName={}", cookieName);
        }

        String accessToken = resolveBearerToken(request);
        String refreshToken = body == null ? null : body.refreshToken;

        log.info("后台登出：tenantId={}, hasAccessToken={}, refreshTokenLen={}, deviceId={}",
                tenantId,
                StringUtils.hasText(accessToken),
                refreshToken == null ? 0 : refreshToken.length(),
                maskDeviceId(deviceId));

        JsonNode accessResult = revokeAndParse(tenantId, accessToken, "access_token", deviceId);
        JsonNode refreshResult = revokeAndParse(tenantId, refreshToken, "refresh_token", deviceId);

        var out = objectMapper.createObjectNode();
        out.set("access", accessResult == null ? objectMapper.nullNode() : accessResult);
        out.set("refresh", refreshResult == null ? objectMapper.nullNode() : refreshResult);
        return out;
    }

    private JsonNode parseJson(String raw) {
        try {
            if (raw == null) {
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

    private JsonNode revokeAndParse(String tenantId, String token, String tokenTypeHint, String deviceId) {
        if (!StringUtils.hasText(token)) {
            return objectMapper.createObjectNode()
                    .put("attempted", false)
                    .put("revoked", false);
        }
        try {
            String raw = adminTokenService.revokeToken(tenantId, token, tokenTypeHint, deviceId).getBody();
            JsonNode parsed = parseJson(raw);
            boolean revoked = parsed != null && parsed.has("revoked") && parsed.get("revoked").asBoolean(false);

            // 说明：当 revoked=false 时，补充一条可定位的日志（不输出 token 原文）
            if (!revoked && log.isDebugEnabled()) {
                log.debug("后台撤销结果 revoked=false：tenantId={}, tokenTypeHint={}, tokenLen={}, token={}, deviceId={}, rawSnippet={}",
                        tenantId,
                        tokenTypeHint,
                        token.length(),
                        maskToken(token),
                        maskDeviceId(deviceId),
                        LogSafeUtil.sanitizeAndTruncate(raw, 256));
            }
            var out = objectMapper.createObjectNode();
            out.put("attempted", true);
            out.put("revoked", revoked);
            out.set("raw", parsed == null ? objectMapper.nullNode() : parsed);
            return out;
        } catch (Exception e) {
            // 说明：登出失败仍然返回 attempted=true，便于前端与日志排查
            if (log.isDebugEnabled()) {
                log.warn("后台撤销 token 失败：tokenTypeHint={}, msg={}", tokenTypeHint, e.getMessage());
            }
            return objectMapper.createObjectNode()
                    .put("attempted", true)
                    .put("revoked", false)
                    .put("error", e.getMessage() == null ? "" : e.getMessage());
        }
    }

    private static String maskToken(String token) {
        if (!StringUtils.hasText(token)) {
            return "";
        }
        String v = token.trim();
        if (v.length() <= 10) {
            return "****";
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    private static String resolveBearerToken(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String auth = request.getHeader("Authorization");
        if (!StringUtils.hasText(auth)) {
            return null;
        }
        String v = auth.trim();
        if (!v.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = v.substring(7).trim();
        return StringUtils.hasText(token) ? token : null;
    }

    /**
     * 获取或生成后台 deviceId。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>同一个管理员账号允许多端同时在线，需要 deviceId 区分不同会话。</li>
     *   <li>deviceId 通过 HttpOnly cookie 保存，前端 JS 不需要读取。</li>
     * </ul>
     */
    private String getOrCreateDeviceId(HttpServletRequest request, HttpServletResponse response) {
        String cookieName = adminAuthProperties.getDeviceIdCookieName();
        if (!StringUtils.hasText(cookieName)) {
            cookieName = "BOOT_CLOUD_ADMIN_DEVICE_ID";
        }

        boolean hadValidDeviceId = StringUtils.hasText(deviceIdCookieService.readDeviceId(
                request,
                cookieName,
                adminAuthProperties.getDeviceIdCookieMaxAgeSeconds()
        ));
        String newOrExisting = deviceIdCookieService.getOrCreateDeviceId(
                request,
                response,
                cookieName,
                adminAuthProperties.getDeviceIdCookieMaxAgeSeconds(),
                adminAuthProperties.getDeviceIdCookiePath(),
                adminAuthProperties.getDeviceIdCookieSameSite(),
                adminAuthProperties.isDeviceIdCookieSecure(),
                adminAuthProperties.getDeviceIdCookieDomain()
        );
        if (!hadValidDeviceId) {
            log.debug("后台 deviceId 已生成并写入 cookie：cookieName={}, deviceId={}", cookieName, maskDeviceId(newOrExisting));
        }
        return newOrExisting;
    }

    private String maskDeviceId(String deviceId) {
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
