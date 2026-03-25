package com.bootcloud.auth.controller;

import com.bootcloud.auth.core.OAuthService;
import com.bootcloud.auth.core.dto.IntrospectResponse;
import com.bootcloud.auth.core.tenant.TenantResolver;
import com.bootcloud.auth.core.error.OAuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
public class OAuth2TokenIntrospectionController {

    private final OAuthService oAuthService;
    private final TenantResolver tenantResolver;

    public OAuth2TokenIntrospectionController(OAuthService oAuthService, TenantResolver tenantResolver) {
        this.oAuthService = oAuthService;
        this.tenantResolver = tenantResolver;
    }


    @PostMapping(value = "/oauth/check_token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public IntrospectResponse checkToken(
            HttpServletRequest request,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam("token") String token
    ) {
        long tenantId = tenantResolver.resolveTenantId(request);

        // 说明：兼容两种调用方式
        // 1) 旧调用方式：form 里显式传 client_id/client_secret
        // 2) 标准 OAuth2 资源服务 introspection：只传 token，client 使用 HTTP Basic 认证
        BasicClient basic = resolveBasicClient(request);
        String resolvedClientId = clientId != null ? clientId : (basic != null ? basic.clientId : null);
        String resolvedSecret = clientSecret != null ? clientSecret : (basic != null ? basic.clientSecret : null);

        if (resolvedClientId == null || resolvedClientId.isBlank()) {
            throw OAuthException.invalidRequest("missing client_id");
        }
        return oAuthService.checkToken(tenantId, resolvedClientId, resolvedSecret, token);
    }

    private BasicClient resolveBasicClient(HttpServletRequest request) {
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
            BasicClient bc = new BasicClient();
            bc.clientId = decoded.substring(0, idx);
            bc.clientSecret = decoded.substring(idx + 1);
            return bc;
        } catch (Exception e) {
            return null;
        }
    }

    private static class BasicClient {
        String clientId;
        String clientSecret;
    }
}
