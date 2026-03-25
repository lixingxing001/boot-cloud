package com.bootcloud.auth.controller;

import com.bootcloud.auth.core.OAuthService;
import com.bootcloud.auth.core.dto.TokenResponse;
import com.bootcloud.auth.core.tenant.TenantResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
public class OAuth2TokenController {

    private final OAuthService oAuthService;
    private final TenantResolver tenantResolver;

    public OAuth2TokenController(OAuthService oAuthService, TenantResolver tenantResolver) {
        this.oAuthService = oAuthService;
        this.tenantResolver = tenantResolver;
    }

    @PostMapping(value = "/oauth/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public TokenResponse token(
            HttpServletRequest request,
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "refresh_token", required = false) String refreshToken
    ) {
        long tenantId = tenantResolver.resolveTenantId(request);
        // 兼容两种 client 认证方式：
        // 1) form: client_id + client_secret
        // 2) HTTP Basic: Authorization: Basic base64(client_id:client_secret)
        String resolvedSecret = clientSecret != null ? clientSecret : resolveBasicClientSecret(request, clientId);
        return oAuthService.token(
                tenantId,
                grantType,
                clientId,
                resolvedSecret,
                scope,
                username,
                password,
                code,
                codeVerifier,
                redirectUri,
                refreshToken
        );
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
