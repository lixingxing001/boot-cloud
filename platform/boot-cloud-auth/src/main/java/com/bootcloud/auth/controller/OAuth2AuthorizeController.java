package com.bootcloud.auth.controller;

import com.bootcloud.auth.core.OAuthService;
import com.bootcloud.auth.core.dto.AuthorizeResponse;
import com.bootcloud.auth.core.tenant.TenantResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2AuthorizeController {

    private final OAuthService oAuthService;
    private final TenantResolver tenantResolver;

    public OAuth2AuthorizeController(OAuthService oAuthService, TenantResolver tenantResolver) {
        this.oAuthService = oAuthService;
        this.tenantResolver = tenantResolver;
    }

    @PostMapping(value = "/oauth/authorize", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public AuthorizeResponse authorize(
            HttpServletRequest request,
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password
    ) {
        // 设计取舍：
        // - 本项目 authorization_code 流程只提供 API，不提供页面。
        // - 当前阶段为了跑通最小闭环，直接在 authorize 阶段做一次“用户名/密码”校验并签发 code。
        // - 后期可切换为：前端登录态 + consent 确认 + PKCE。
        long tenantId = tenantResolver.resolveTenantId(request);
        return oAuthService.authorize(tenantId, responseType, clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, username, password);
    }
}
