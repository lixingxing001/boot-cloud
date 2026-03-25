package com.bootcloud.auth.controller;

import com.bootcloud.auth.core.device.DeviceSessionService;
import com.bootcloud.auth.core.tenant.TenantResolver;
import com.bootcloud.auth.core.error.OAuthException;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Util;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth2 扩展端点：登录设备管理。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该端点放在 /oauth/** 下，便于与 OAuth2 能力聚合。</li>
 *   <li>必须做 client 认证（Basic 或 form secret），避免任何人直接枚举用户设备。</li>
 * </ul>
 */
@Slf4j
@RestController
public class OAuthDeviceSessionController {

    private final TenantResolver tenantResolver;
    private final DeviceSessionService deviceSessionService;

    public OAuthDeviceSessionController(TenantResolver tenantResolver, DeviceSessionService deviceSessionService) {
        this.tenantResolver = tenantResolver;
        this.deviceSessionService = deviceSessionService;
    }

    @PostMapping(value = "/oauth/device/sessions", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> sessions(
            HttpServletRequest request,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam("user_id") String userId
    ) {
        long tenantId = tenantResolver.resolveTenantId(request);
        String resolvedSecret = clientSecret != null ? clientSecret : resolveBasicClientSecret(request, clientId);
        SaOAuth2Util.checkClientSecret(clientId, resolvedSecret);

        long uid = parseUserId(userId);
        if (uid <= 0) {
            throw OAuthException.invalidRequest("invalid user_id");
        }

        List<DeviceSessionService.DeviceSessionView> list = deviceSessionService.listSessions(tenantId, clientId, uid, 50);
        Map<String, Object> out = new HashMap<>();
        out.put("tenantId", tenantId);
        out.put("clientId", clientId);
        out.put("userId", String.valueOf(uid));
        out.put("sessions", list);
        out.put("serverTime", System.currentTimeMillis());
        if (log.isDebugEnabled()) {
            log.debug("设备会话列表返回：tenantId={}, clientId={}, userId={}, count={}", tenantId, clientId, uid, list == null ? 0 : list.size());
        }
        return out;
    }

    @PostMapping(value = "/oauth/device/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> revokeByDevice(
            HttpServletRequest request,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam("user_id") String userId,
            @RequestParam("device_id") String deviceId
    ) {
        long tenantId = tenantResolver.resolveTenantId(request);
        String resolvedSecret = clientSecret != null ? clientSecret : resolveBasicClientSecret(request, clientId);
        SaOAuth2Util.checkClientSecret(clientId, resolvedSecret);

        long uid = parseUserId(userId);
        if (uid <= 0) {
            throw OAuthException.invalidRequest("invalid user_id");
        }
        if (!StringUtils.hasText(deviceId)) {
            throw OAuthException.invalidRequest("missing device_id");
        }

        var r = deviceSessionService.revokeByDevice(tenantId, clientId, uid, deviceId);
        Map<String, Object> out = new HashMap<>();
        out.put("tenantId", tenantId);
        out.put("clientId", clientId);
        out.put("userId", String.valueOf(uid));
        out.put("deviceId", deviceId);
        out.put("removedFromSessionList", r.removedFromSessionList());
        out.put("revokedAccessToken", r.revokedAccessToken());
        out.put("revokedRefreshToken", r.revokedRefreshToken());
        out.put("serverTime", System.currentTimeMillis());
        if (log.isInfoEnabled()) {
            log.info("远程登出设备完成：tenantId={}, clientId={}, userId={}, deviceId={}, revokedAccess={}, revokedRefresh={}",
                    tenantId, clientId, uid, maskDeviceId(deviceId), r.revokedAccessToken(), r.revokedRefreshToken());
        }
        return out;
    }

    private static long parseUserId(String userId) {
        try {
            return Long.parseLong(String.valueOf(userId).trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private static String maskDeviceId(String deviceId) {
        if (!StringUtils.hasText(deviceId)) return "";
        String v = deviceId.trim();
        if (v.length() <= 8) return v;
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    private String resolveBasicClientSecret(HttpServletRequest request, String clientId) {
        String auth = request.getHeader("Authorization");
        if (auth == null) {
            return null;
        }
        String val = auth.trim();
        if (!val.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(val.substring(6).trim()), StandardCharsets.UTF_8);
            int idx = decoded.indexOf(':');
            if (idx <= 0) {
                return null;
            }
            String cid = decoded.substring(0, idx);
            String secret = decoded.substring(idx + 1);
            if (!cid.equals(clientId)) {
                return null;
            }
            return secret;
        } catch (Exception e) {
            return null;
        }
    }
}

