package com.bootcloud.auth.controller;

import com.bootcloud.auth.core.OAuthService;
import com.bootcloud.auth.core.dto.RevokeResponse;
import com.bootcloud.auth.core.tenant.TenantResolver;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@RestController
public class OAuth2TokenRevocationController {

    private final OAuthService oAuthService;
    private final TenantResolver tenantResolver;

    public OAuth2TokenRevocationController(OAuthService oAuthService, TenantResolver tenantResolver) {
        this.oAuthService = oAuthService;
        this.tenantResolver = tenantResolver;
    }

    @PostMapping(value = "/oauth/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public RevokeResponse revoke(
            HttpServletRequest request,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint
    ) {
        long tenantId = tenantResolver.resolveTenantId(request);
        String resolvedSecret = clientSecret != null ? clientSecret : resolveBasicClientSecret(request, clientId);

        // 说明：撤销接口必须具备可观测性，便于排查 revoked=false 的原因
        // 注意：不要输出 token 原文或 client_secret，这里只输出长度与脱敏片段
        String deviceId = resolveDeviceId(request);
        if (log.isDebugEnabled()) {
            log.debug("收到 /oauth/revoke：tenantId={}, clientId={}, tokenTypeHint={}, tokenLen={}, token={}, deviceId={}, hasSecretFromForm={}, hasSecretFromBasic={}",
                    tenantId,
                    safe(clientId),
                    safe(tokenTypeHint),
                    token == null ? 0 : token.length(),
                    maskToken(token),
                    maskDeviceId(deviceId),
                    clientSecret != null,
                    request.getHeader("Authorization") != null);
        }
        return oAuthService.revoke(tenantId, clientId, resolvedSecret, token, tokenTypeHint, deviceId);
    }

    private static String resolveDeviceId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String fromParam = request.getParameter("device_id");
        if (fromParam != null && !fromParam.isBlank()) {
            return fromParam.trim();
        }
        String fromHeader = request.getHeader("X-Device-Id");
        if (fromHeader != null && !fromHeader.isBlank()) {
            return fromHeader.trim();
        }
        return null;
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private static String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        String v = token.trim();
        if (v.length() <= 10) {
            return "****";
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    private static String maskDeviceId(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            return "";
        }
        String v = deviceId.trim();
        if (v.length() <= 8) {
            return v;
        }
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
