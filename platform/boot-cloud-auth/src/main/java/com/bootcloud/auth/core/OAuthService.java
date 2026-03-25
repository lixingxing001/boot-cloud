package com.bootcloud.auth.core;

import com.bootcloud.auth.core.admin.AdminAuthoritiesService;
import com.bootcloud.auth.core.admin.AdminPrincipal;
import com.bootcloud.auth.core.admin.AdminUserAuthenticator;
import com.bootcloud.auth.core.device.DeviceSessionService;
import com.bootcloud.auth.core.dto.AuthorizeResponse;
import com.bootcloud.auth.core.dto.IntrospectResponse;
import com.bootcloud.auth.core.dto.RevokeResponse;
import com.bootcloud.auth.core.dto.TokenResponse;
import com.bootcloud.auth.core.error.OAuthException;
import com.bootcloud.auth.core.pkce.OAuthPkceStore;
import com.bootcloud.auth.core.tenant.TenantContext;
import com.bootcloud.auth.core.tenant.TenantStatusService;
import com.bootcloud.auth.core.user.UserAuthenticator;
import com.bootcloud.auth.core.user.UserPrincipal;
import com.bootcloud.auth.config.AuthServerProperties;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Util;
import cn.dev33.satoken.oauth2.model.AccessTokenModel;
import cn.dev33.satoken.oauth2.model.ClientTokenModel;
import cn.dev33.satoken.oauth2.model.CodeModel;
import cn.dev33.satoken.oauth2.model.RefreshTokenModel;
import cn.dev33.satoken.oauth2.model.RequestAuthModel;
import cn.dev33.satoken.oauth2.model.SaClientModel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
@Service
public class OAuthService {

    private final UserAuthenticator userAuthenticator;
    private final AdminUserAuthenticator adminUserAuthenticator;
    private final AdminAuthoritiesService adminAuthoritiesService;
    private final OAuthPkceStore pkceStore;
    private final AuthServerProperties properties;
    private final DeviceSessionService deviceSessionService;
    private final TenantStatusService tenantStatusService;

    public OAuthService(
            UserAuthenticator userAuthenticator,
            AdminUserAuthenticator adminUserAuthenticator,
            AdminAuthoritiesService adminAuthoritiesService,
            OAuthPkceStore pkceStore,
            AuthServerProperties properties,
            DeviceSessionService deviceSessionService,
            TenantStatusService tenantStatusService
    ) {
        this.userAuthenticator = userAuthenticator;
        this.adminUserAuthenticator = adminUserAuthenticator;
        this.adminAuthoritiesService = adminAuthoritiesService;
        this.pkceStore = pkceStore;
        this.properties = properties;
        this.deviceSessionService = deviceSessionService;
        this.tenantStatusService = tenantStatusService;
    }

    /**
     * OAuth2 授权端点（API 形式）。
     *
     * <p>当前实现用于最小可用链路：</p>
     * <ul>
     *   <li>仅支持 {@code response_type=code}。</li>
     *   <li>为简化，直接通过 {@code username/password} 做资源所有者认证（不提供页面）。</li>
     * </ul>
     *
     * <p>后期扩展方向：</p>
     * <ul>
     *   <li>替换为前端登录态 + 授权确认（consent）机制。</li>
     *   <li>增加 PKCE、增加更严格的 redirect_uri 校验策略。</li>
     * </ul>
     */
    public AuthorizeResponse authorize(
            long tenantId,
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String username,
            String password
    ) {
        if (tenantId <= 0) {
            throw OAuthException.invalidRequest("missing tenant_id");
        }
        // 说明：授权码链路属于用户侧入口，租户禁用后需要拒绝。
        enforceTenantEnabledForUserRequest(tenantId, "authorize");
        if (!"code".equalsIgnoreCase(responseType)) {
            throw OAuthException.unsupportedResponseType("response_type must be code");
        }

        // 说明：client 的所有信息来自 SaOAuth2Util（底层会走我们注入的 DB Template）
        // - redirect_uri 白名单：SaOAuth2Util.checkRightUrl
        // - scope 合法性：SaOAuth2Util.checkContract
        //
        // 说明：redirect_uri 对授权码签发来说强烈建议必传。
        // 但考虑到移动端与测试场景，这里做一个“无歧义自动兜底”：
        // 1) 若请求未传 redirect_uri 且该 client 在 DB 里只配置了 1 个回调地址，则自动选用该地址；
        // 2) 若配置了多个回调地址，则必须显式传 redirect_uri，避免歧义与误跳转风险。
        SaClientModel clientModel = SaOAuth2Util.checkClientModel(clientId);
        String resolvedRedirectUri = redirectUri;
        if (!StringUtils.hasText(resolvedRedirectUri)) {
            List<String> allowUrls = Arrays.stream(String.valueOf(clientModel.allowUrl).split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .toList();
            if (allowUrls.size() == 1) {
                resolvedRedirectUri = allowUrls.get(0);
                log.debug("authorize redirect_uri 自动兜底：clientId={}, redirectUri={}", clientId, resolvedRedirectUri);
            } else {
                log.warn("authorize 缺少 redirect_uri 且回调地址数量>1：clientId={}, allowUrlCount={}", clientId, allowUrls.size());
                throw OAuthException.invalidRequest("missing redirect_uri");
            }
        }
        SaOAuth2Util.checkRightUrl(clientId, resolvedRedirectUri);

        // 说明：你已确认不再使用 Sa-Token 登录态作为“授权码中间态”。
        // 因此 /oauth/authorize 仅支持 username/password 方式签发 code。
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw OAuthException.invalidRequest("missing username or password");
        }
        UserPrincipal principal = userAuthenticator.authenticatePassword(tenantId, username, password);
        Object loginId = principal.userId();

        if (!clientModel.getIsCode()) {
            throw OAuthException.unauthorizedClient("authorization_code is not enabled for this client");
        }
        String resolvedScope = principal == null
                ? resolveScopeForClient(scope, clientModel.contractScope)
                : resolveScopeForRequest(scope, clientModel.contractScope, principal);

        // 说明：后台管理员 scope（admin）不允许通过 /oauth/authorize 走授权码签发，避免 scope 提权。
        // 约定：admin scope 只能由 grant_type=admin_password 签发。
        if (containsScope(resolvedScope, "admin")) {
            throw OAuthException.invalidScope("admin scope is not allowed in authorization_code flow");
        }
        SaOAuth2Util.checkContract(clientId, resolvedScope);

        // 设计取舍：
        // - 本项目当前不做“授权确认页面”，因此这里默认视为用户已同意 scope，直接落库授权记录并签发 code。
        // - 后期如果需要前端展示 consent，可改为：isGrant=false 时返回 need_confirm，再由前端调用 /oauth/doConfirm。
        if (!SaOAuth2Util.isGrant(loginId, clientId, resolvedScope)) {
            SaOAuth2Util.saveGrantScope(clientId, loginId, resolvedScope);
        }

        RequestAuthModel request = new RequestAuthModel()
                .setClientId(clientId)
                .setLoginId(loginId)
                .setRedirectUri(resolvedRedirectUri)
                .setResponseType("code")
                .setState(state)
                .setScope(resolvedScope);

        String code = SaOAuth2Util.generateCode(request).code;
        // 如果携带 PKCE 参数，则将 challenge 与 code 做一次性绑定。
        // - 兼容两种 challenge_method：plain / S256（当前要求都支持）
        // - TTL 与授权码一致，避免 “code 已过期但 pkce 未过期” 的残留风险
        if (StringUtils.hasText(codeChallenge)) {
            if (StringUtils.hasText(codeChallengeMethod)) {
                String m = codeChallengeMethod.trim();
                if (!m.equalsIgnoreCase("plain") && !m.equalsIgnoreCase("S256")) {
                    throw OAuthException.invalidRequest("unsupported code_challenge_method");
                }
            }
            pkceStore.save(tenantId, code, codeChallenge, codeChallengeMethod, Math.max(properties.getAuthorizationCodeTtlSeconds(), 1L));
        }
        String redirect = SaOAuth2Util.buildRedirectUri(resolvedRedirectUri, code, state);
        return AuthorizeResponse.ok(code, state, redirect);
    }

    /**
     * OAuth2 token 端点，支持以下 grant：
     * <ul>
     *   <li>password</li>
     *   <li>client_credentials</li>
     *   <li>authorization_code</li>
     *   <li>refresh_token</li>
     *   <li>admin_password</li>
     * </ul>
     *
     * <p>注意：</p>
     * <ul>
     *   <li>token 为随机串（Bearer），状态保存在 Redis。</li>
     *   <li>所有请求必须携带 {@code X-Tenant-Id}，租户值由网关或 BFF 负责解析并注入。</li>
     *   <li>client 校验来自平台 OAuth Client 配置。</li>
     * </ul>
     */
    public TokenResponse token(
            long tenantId,
            String grantType,
            String clientId,
            String clientSecret,
            String scope,
            String username,
            String password,
            String code,
            String codeVerifier,
            String redirectUri,
            String refreshToken
    ) {
        if (tenantId <= 0) {
            throw OAuthException.invalidRequest("missing tenant_id");
        }
        String gt = StringUtils.hasText(grantType) ? grantType.trim().toLowerCase() : "";
        log.debug("oauth token request: tenantId={}, grantType={}, clientId={}", tenantId, gt, clientId);
        return switch (gt) {
            case "password" -> grantPassword(tenantId, clientId, clientSecret, scope, username, password);
            case "client_credentials" -> grantClientCredentials(tenantId, clientId, clientSecret, scope);
            case "authorization_code" -> grantAuthorizationCode(tenantId, clientId, clientSecret, code, codeVerifier, redirectUri);
            case "refresh_token" -> grantRefreshToken(tenantId, clientId, clientSecret, refreshToken);
            case "admin_password" -> grantAdminPassword(tenantId, clientId, clientSecret, username, password);
            default -> throw OAuthException.unsupportedGrantType("unsupported grant_type: " + grantType);
        };
    }

    public IntrospectResponse checkToken(long tenantId, String token) {
        if (tenantId <= 0) {
            throw OAuthException.invalidRequest("missing tenant_id");
        }
        AccessTokenModel at = readAccessTokenForAdminAwareTenant(tenantId, token);
        if (at != null) {
            // 说明：后台 admin token 不受租户 status=0 限制，用户 token 需要受限。
            if (!containsScope(at.scope, "admin")) {
                enforceTenantEnabledForUserRequest(tenantId, "check_token_access_token");
            }
            IntrospectResponse r = IntrospectResponse.active(at);
            enrichAdminAuthoritiesIfNeeded(tenantId, r);
            return r;
        }

        // client_credentials 走 Sa-Token 的 client_token（底层仍然是随机串 + Redis）
        ClientTokenModel ct = readClientTokenForAdminAwareTenant(tenantId, token);
        if (ct != null) {
            return IntrospectResponse.active(ct);
        }
        return IntrospectResponse.inactive();
    }

    public IntrospectResponse checkToken(long tenantId, String clientId, String clientSecret, String token) {
        if (tenantId <= 0) {
            throw OAuthException.invalidRequest("missing tenant_id");
        }
        SaOAuth2Util.checkClientSecret(clientId, clientSecret);
        return checkToken(tenantId, token);
    }

    /**
     * 给 admin scope 的 token 自省结果回填 authorities。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>管理端服务 资源服务化后会使用该字段做权限校验。</li>
     *   <li>普通用户 token 不回填。</li>
     * </ul>
     */
    private void enrichAdminAuthoritiesIfNeeded(long tenantId, IntrospectResponse r) {
        if (r == null || !r.isActive()) {
            return;
        }
        if (!containsScope(r.getScope(), "admin")) {
            return;
        }
        if (properties == null || properties.getAdminAuthorities() == null || !properties.getAdminAuthorities().isEnabled()) {
            return;
        }
        if (!StringUtils.hasText(r.getUserId())) {
            return;
        }
        try {
            long adminId = Long.parseLong(r.getUserId().trim());
            if (adminId <= 0) {
                return;
            }
            if (!adminAuthoritiesService.isTenantAllowed(tenantId, adminId)) {
                log.warn("管理员 token 自省租户不匹配，返回 inactive：tenantId={}, adminId={}", tenantId, adminId);
                r.setActive(false);
                r.setAuthorities(List.of());
                return;
            }
            r.setAuthorities(adminAuthoritiesService.getAuthorities(tenantId, adminId));
        } catch (NumberFormatException ignore) {
            // 说明：如果 token 的 sub 异常，保持不回填，避免自省报错影响正常请求
        }
    }

    public RevokeResponse revoke(long tenantId, String clientId, String clientSecret, String token, String tokenTypeHint, String deviceId) {
        if (tenantId <= 0) {
            throw OAuthException.invalidRequest("missing tenant_id");
        }
        SaClientModel clientModel = SaOAuth2Util.checkClientSecret(clientId, clientSecret);
        String hint = tokenTypeHint == null ? "" : tokenTypeHint.trim().toLowerCase();
        long sessionTenantId = resolveRevokeSessionTenantId(tenantId, clientId, token, hint, clientModel);

        boolean revoked = false;
        String loginIdForSession = null;

        // 说明：撤销接口需要足够的调试日志以定位 revoked=false
        // 注意：不要输出 token 原文，这里只输出脱敏片段与长度
        if (log.isDebugEnabled()) {
            log.debug("开始撤销 token：requestTenantId={}, sessionTenantId={}, clientId={}, tokenTypeHint(raw)={}, tokenTypeHint(normalized)={}, tokenLen={}, token={}",
                    tenantId,
                    sessionTenantId,
                    safe(clientId),
                    safe(tokenTypeHint),
                    hint,
                    token == null ? 0 : token.length(),
                    maskToken(token));
        }

        if (hint.isEmpty() || "access_token".equals(hint)) {
            AccessTokenModel at = withTenantContext(sessionTenantId, () -> SaOAuth2Util.getAccessToken(token));
            if (at == null) {
                if (log.isDebugEnabled()) {
                    log.debug("access_token 未找到：sessionTenantId={}, clientId={}, token={}", sessionTenantId, safe(clientId), maskToken(token));
                }
            } else if (!clientId.equals(at.clientId)) {
                if (log.isDebugEnabled()) {
                    log.debug("access_token client 不匹配：sessionTenantId={}, expectClientId={}, actualClientId={}, token={}",
                            sessionTenantId,
                            safe(clientId),
                            safe(at.clientId),
                            maskToken(token));
                }
            } else {
                withTenantContext(sessionTenantId, () -> {
                    SaOAuth2Util.revokeAccessToken(token);
                    return null;
                });
                revoked = true;
                loginIdForSession = at.loginId == null ? null : String.valueOf(at.loginId);
            }
        }

        if (hint.isEmpty() || "refresh_token".equals(hint)) {
            RefreshTokenModel rt = withTenantContext(sessionTenantId, () -> SaOAuth2Util.getRefreshToken(token));
            if (rt == null) {
                if (log.isDebugEnabled()) {
                    log.debug("refresh_token 未找到：sessionTenantId={}, clientId={}, token={}", sessionTenantId, safe(clientId), maskToken(token));
                }
            } else if (!clientId.equals(rt.clientId)) {
                if (log.isDebugEnabled()) {
                    log.debug("refresh_token client 不匹配：sessionTenantId={}, expectClientId={}, actualClientId={}, token={}",
                            sessionTenantId,
                            safe(clientId),
                            safe(rt.clientId),
                            maskToken(token));
                }
            } else {
                // Sa-Token 默认 revoke 只处理 access_token，这里补充 refresh_token 的撤销，方便网关/前端统一调用。
                String accessTokenValue = withTenantContext(sessionTenantId, () -> {
                    SaOAuth2Util.saOAuth2Template.deleteRefreshToken(token);
                    SaOAuth2Util.saOAuth2Template.deleteRefreshTokenIndex(clientId, rt.loginId);
                    // 同时撤销该用户在此 client 下的 access_token（按 index 获取并删除）
                    return SaOAuth2Util.saOAuth2Template.getAccessTokenValue(clientId, rt.loginId);
                });
                if (StringUtils.hasText(accessTokenValue)) {
                    withTenantContext(sessionTenantId, () -> {
                        SaOAuth2Util.revokeAccessToken(accessTokenValue);
                        return null;
                    });
                }
                if (log.isDebugEnabled()) {
                    log.debug("refresh_token 已撤销：sessionTenantId={}, clientId={}, loginId={}, alsoRevokedAccessByIndex={}, token={}",
                            sessionTenantId,
                            safe(clientId),
                            rt.loginId,
                            StringUtils.hasText(accessTokenValue),
                            maskToken(token));
                }
                revoked = true;
                loginIdForSession = rt.loginId == null ? loginIdForSession : String.valueOf(rt.loginId);
            }
        }

        // 说明：如果当前设备执行了登出（revoke），同步把设备会话从列表移除，便于“登录设备管理”展示更准确
        if (revoked && deviceSessionService != null && StringUtils.hasText(deviceId) && StringUtils.hasText(loginIdForSession)) {
            try {
                long uid = Long.parseLong(loginIdForSession.trim());
                deviceSessionService.removeSessionRecordOnly(sessionTenantId, clientId, uid, deviceId.trim());
            } catch (Exception ignore) {
                // ignore
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("撤销完成：requestTenantId={}, sessionTenantId={}, clientId={}, revoked={}, tokenTypeHint(normalized)={}, token={}",
                    tenantId,
                    sessionTenantId,
                    safe(clientId),
                    revoked,
                    hint,
                    maskToken(token));
        }
        return RevokeResponse.ok(revoked);
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
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

    private TokenResponse grantPassword(long tenantId, String clientId, String clientSecret, String scope, String username, String password) {
        enforceTenantEnabledForUserRequest(tenantId, "password");
        SaClientModel clientModel = SaOAuth2Util.checkClientSecret(clientId, clientSecret);
        if (!clientModel.getIsPassword()) {
            throw OAuthException.unauthorizedClient("password grant is not enabled for this client");
        }
        UserPrincipal principal = userAuthenticator.authenticatePassword(tenantId, username, password);
        String resolvedScope = resolveScopeForRequest(scope, clientModel.contractScope, principal);

        // 说明：普通用户的 password grant 不允许申请 admin scope（即使某个 client 错误签约了 admin 也不行）。
        // admin scope 只能通过 grant_type=admin_password。
        if (containsScope(resolvedScope, "admin")) {
            throw OAuthException.invalidScope("admin scope is not allowed in password flow");
        }
        SaOAuth2Util.checkContract(clientId, resolvedScope);
        enforceDeviceLimitBeforeTokenIssue(tenantId, clientId, principal.userId(), "password");

        RequestAuthModel request = new RequestAuthModel()
                .setClientId(clientId)
                .setLoginId(principal.userId())
                .setScope(resolvedScope);
        AccessTokenModel at = SaOAuth2Util.generateAccessToken(request, true);
        recordDeviceSessionIfPossible(tenantId, clientId, principal.userId(), "password");
        return TokenResponse.of(at.accessToken, at.getExpiresIn(), at.refreshToken, normalizeScopeToSpace(at.scope));
    }

    /**
     * 后台管理员账号密码换 token（admin_password -> token）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该 grant 专用于后台管理端，loginId 为管理员 id（来自 t_admin_user）。</li>
     *   <li>scope 强制为 {@code admin}，用于下游（管理端服务）的桥接与权限判定。</li>
     *   <li>推荐由 BFF（boot-cloud-web）调用，前端不暴露 client_secret。</li>
     * </ul>
     */
    private TokenResponse grantAdminPassword(long tenantId, String clientId, String clientSecret, String username, String password) {
        SaClientModel clientModel = SaOAuth2Util.checkClientSecret(clientId, clientSecret);
        // 说明：要求 client 的 contractScope 明确包含 admin，否则拒绝（最小权限）
        if (!containsScope(clientModel.contractScope, "admin")) {
            throw OAuthException.unauthorizedClient("admin_password is not enabled for this client");
        }
        AdminPrincipal principal = adminUserAuthenticator.authenticate(tenantId, username, password);
        long sessionTenantId = principal.sessionTenantId();

        // 强制 scope=admin（不允许前端传 scope 来“加权限”）
        String resolvedScope = "admin";
        SaOAuth2Util.checkContract(clientId, resolvedScope);
        enforceDeviceLimitBeforeTokenIssue(sessionTenantId, clientId, principal.userId(), "admin_password");

        RequestAuthModel request = new RequestAuthModel()
                .setClientId(clientId)
                .setLoginId(principal.userId())
                .setScope(resolvedScope);
        AccessTokenModel at = withTenantContext(sessionTenantId, () -> SaOAuth2Util.generateAccessToken(request, true));
        if (log.isDebugEnabled()) {
            log.debug("admin_password 签发 token：requestTenantId={}, sessionTenantId={}, adminId={}, clientId={}",
                    tenantId, sessionTenantId, principal.userId(), clientId);
        }
        recordDeviceSessionIfPossible(sessionTenantId, clientId, principal.userId(), "admin_password");
        return TokenResponse.of(at.accessToken, at.getExpiresIn(), at.refreshToken, normalizeScopeToSpace(at.scope));
    }

    private TokenResponse grantClientCredentials(long tenantId, String clientId, String clientSecret, String scope) {
        SaClientModel clientModel = SaOAuth2Util.checkClientSecret(clientId, clientSecret);
        if (!clientModel.getIsClient()) {
            throw OAuthException.unauthorizedClient("client_credentials grant is not enabled for this client");
        }
        String resolvedScope = resolveScopeForClient(scope, clientModel.contractScope);
        SaOAuth2Util.checkContract(clientId, resolvedScope);

        ClientTokenModel ct = SaOAuth2Util.generateClientToken(clientId, normalizeScopeToCsv(resolvedScope));
        // OAuth2 标准响应字段里没有 client_token，这里把 client_token 映射为 access_token（Bearer）
        return TokenResponse.of(ct.clientToken, ct.getExpiresIn(), null, normalizeScopeToSpace(ct.scope));
    }

    private TokenResponse grantAuthorizationCode(long tenantId, String clientId, String clientSecret, String code, String codeVerifier, String redirectUri) {
        enforceTenantEnabledForUserRequest(tenantId, "authorization_code");
        if (!StringUtils.hasText(code)) {
            throw OAuthException.invalidRequest("missing code");
        }

        // Sa-Token 原生逻辑不支持 authorization_code 阶段再次传 scope（也不建议这么做）。
        // 这里额外支持 PKCE（当前要求）：
        // - public client（client_secret={public}）可以不传 client_secret，但必须通过 PKCE 校验。
        // - 兼容两种 challenge_method：plain / S256。
        SaClientModel clientModel = SaOAuth2Util.checkClientModel(clientId);
        if (!clientModel.getIsCode()) {
            throw OAuthException.unauthorizedClient("authorization_code grant is not enabled for this client");
        }
        boolean isPublicClient = "{public}".equals(clientModel.clientSecret);

        OAuthPkceStore.PkceBinding binding = pkceStore.get(tenantId, code);
        if (binding != null) {
            if (!StringUtils.hasText(codeVerifier)) {
                throw OAuthException.invalidRequest("missing code_verifier");
            }
            if (!StringUtils.hasText(binding.codeChallenge)) {
                throw OAuthException.invalidGrant("pkce binding missing");
            }
            if (!verifyPkce(binding, codeVerifier)) {
                throw OAuthException.invalidGrant("pkce mismatch");
            }
            // 校验通过后再删除，做到一次性消费（防重放）
            pkceStore.delete(tenantId, code);
            // PKCE 校验通过后：
            // - confidential client：仍然要求 client_secret
            // - public client：允许不传 client_secret（由 PKCE 兜底）
            if (!isPublicClient) {
                SaOAuth2Util.checkGainTokenParam(code, clientId, clientSecret, redirectUri);
            } else {
                // public client 仍要校验 code 与 client/redirect_uri 的绑定关系（不校验 secret）
                CodeModel cm = SaOAuth2Util.saOAuth2Template.getCode(code);
                if (cm == null || !clientId.equals(cm.clientId)) {
                    throw OAuthException.invalidGrant("invalid code");
                }
                if (StringUtils.hasText(redirectUri) && !redirectUri.equals(cm.redirectUri)) {
                    throw OAuthException.invalidGrant("redirect_uri mismatch");
                }
            }
        } else {
            // 未携带 PKCE 绑定：
            // - 如果是 public client，则强制要求走 PKCE（否则任何人知道 code 就能换 token）
            if (isPublicClient) {
                throw OAuthException.invalidGrant("pkce required for public client");
            }
            SaOAuth2Util.checkGainTokenParam(code, clientId, clientSecret, redirectUri);
        }

        CodeModel preIssueCodeModel = SaOAuth2Util.saOAuth2Template.getCode(code);
        if (preIssueCodeModel != null && preIssueCodeModel.loginId != null) {
            enforceDeviceLimitBeforeTokenIssue(tenantId, clientId, preIssueCodeModel.loginId, "authorization_code");
        }

        AccessTokenModel at = SaOAuth2Util.generateAccessToken(code);
        if (at != null && at.loginId != null) {
            recordDeviceSessionIfPossible(tenantId, clientId, String.valueOf(at.loginId), "authorization_code");
        }
        return TokenResponse.of(at.accessToken, at.getExpiresIn(), at.refreshToken, normalizeScopeToSpace(at.scope));
    }

    private static boolean verifyPkce(OAuthPkceStore.PkceBinding binding, String codeVerifier) {
        String verifier = codeVerifier.trim();
        if (verifier.isEmpty()) {
            return false;
        }
        // RFC 7636: verifier 长度 43~128，这里只做最小校验，避免误伤现网数据
        if (verifier.length() < 8 || verifier.length() > 256) {
            return false;
        }
        String method = binding.codeChallengeMethod == null ? "plain" : binding.codeChallengeMethod.trim();
        if (method.equalsIgnoreCase("plain")) {
            return verifier.equals(binding.codeChallenge);
        }
        if (method.equalsIgnoreCase("S256")) {
            return s256(verifier).equals(binding.codeChallenge);
        }
        return false;
    }

    private static String s256(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (Exception e) {
            throw OAuthException.serverError("pkce_sha256_failed");
        }
    }

    private TokenResponse grantRefreshToken(long tenantId, String clientId, String clientSecret, String refreshToken) {
        if (!StringUtils.hasText(refreshToken)) {
            throw OAuthException.invalidRequest("missing refresh_token");
        }
        SaClientModel clientModel = SaOAuth2Util.checkClientSecret(clientId, clientSecret);
        long sessionTenantId = resolveRefreshSessionTenantId(tenantId, clientId, refreshToken, clientModel);
        RefreshTokenModel rt = withTenantContext(sessionTenantId, () -> SaOAuth2Util.getRefreshToken(refreshToken));
        if (rt == null) {
            throw OAuthException.invalidGrant("invalid refresh_token");
        }
        if (!clientId.equals(rt.clientId)) {
            throw OAuthException.invalidGrant("refresh_token does not belong to client");
        }
        // 说明：管理员 refresh 不受租户状态影响，用户 refresh 需要校验租户启用状态。
        if (!containsScope(rt.scope, "admin")) {
            enforceTenantEnabledForUserRequest(sessionTenantId, "refresh_token");
        }
        if (rt != null && rt.loginId != null) {
            enforceDeviceLimitBeforeTokenIssue(sessionTenantId, clientId, rt.loginId, "refresh_token");
        }
        AccessTokenModel at = withTenantContext(sessionTenantId, () -> SaOAuth2Util.refreshAccessToken(refreshToken));
        // 说明：refresh 成功也视为设备活跃，刷新设备列表 lastSeen
        if (at != null && at.loginId != null) {
            if (log.isDebugEnabled()) {
                log.debug("refresh_token 刷新完成：requestTenantId={}, sessionTenantId={}, clientId={}, loginId={}",
                        tenantId, sessionTenantId, clientId, at.loginId);
            }
            recordDeviceSessionIfPossible(sessionTenantId, clientId, String.valueOf(at.loginId), "refresh_token");
        }
        return TokenResponse.of(at.accessToken, at.getExpiresIn(), at.refreshToken, normalizeScopeToSpace(at.scope));
    }

    private void recordDeviceSessionIfPossible(long tenantId, String clientId, String userId, String grantType) {
        if (deviceSessionService == null) {
            return;
        }
        long uid = parseUserId(userId);
        if (uid <= 0) {
            return;
        }
        deviceSessionService.recordOnTokenIssued(tenantId, clientId, uid, grantType);
    }

    /**
     * 签发 token 前执行设备数上限策略。
     */
    private void enforceDeviceLimitBeforeTokenIssue(long tenantId, String clientId, Object userId, String grantType) {
        if (deviceSessionService == null) {
            return;
        }
        long uid = parseUserId(userId);
        if (uid <= 0) {
            return;
        }
        DeviceSessionService.DeviceLimitCheckResult check = deviceSessionService.preCheckBeforeTokenIssue(tenantId, clientId, uid, grantType);
        if (check == null || check.allowed()) {
            return;
        }
        log.warn("登录设备数超限，拒绝签发 token：tenantId={}, clientId={}, userId={}, grantType={}, policy={}, maxDevices={}, reason={}, currentDevice={}",
                tenantId,
                safe(clientId),
                uid,
                safe(grantType),
                check.policy(),
                check.maxDevices(),
                check.reason(),
                maskDevice(check.currentDeviceId()));
        throw OAuthException.invalidGrant("device_limit_exceeded");
    }

    /**
     * 读取 access_token，兼容系统级管理员会话固定落在 tenant_id=0。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>普通租户管理员与普通用户 token 继续优先从请求租户读取。</li>
     *   <li>若请求租户未命中，再回退读取 tenant_id=0 的系统级管理员 token。</li>
     *   <li>这样切换默认租户后，super_admin 旧 token 仍能被后台链路识别。</li>
     * </ul>
     */
    private AccessTokenModel readAccessTokenForAdminAwareTenant(long tenantId, String token) {
        AccessTokenModel tokenInRequestTenant = readAccessTokenInTenant(tenantId, token);
        if (tokenInRequestTenant != null) {
            return tokenInRequestTenant;
        }
        if (tenantId <= 0) {
            return null;
        }

        AccessTokenModel tokenInSystemTenant = readAccessTokenInTenant(0L, token);
        if (isSystemAdminAccessToken(tenantId, tokenInSystemTenant)) {
            if (log.isDebugEnabled()) {
                log.debug("access_token 未命中请求租户，回退命中系统级会话：requestTenantId={}, loginId={}, clientId={}",
                        tenantId,
                        tokenInSystemTenant.loginId,
                        safe(tokenInSystemTenant.clientId));
            }
            return tokenInSystemTenant;
        }
        return null;
    }

    /**
     * 读取 client_token，兼容系统级基础设施 client 固定落在 tenant_id=0。
     */
    private ClientTokenModel readClientTokenForAdminAwareTenant(long tenantId, String token) {
        ClientTokenModel tokenInRequestTenant = readClientTokenInTenant(tenantId, token);
        if (tokenInRequestTenant != null) {
            return tokenInRequestTenant;
        }
        if (tenantId <= 0) {
            return null;
        }
        ClientTokenModel tokenInSystemTenant = readClientTokenInTenant(0L, token);
        if (tokenInSystemTenant != null && log.isDebugEnabled()) {
            log.debug("client_token 未命中请求租户，回退命中系统级会话：requestTenantId={}, clientId={}",
                    tenantId,
                    safe(tokenInSystemTenant.clientId));
        }
        return tokenInSystemTenant;
    }

    private AccessTokenModel readAccessTokenInTenant(long tenantId, String token) {
        if (!StringUtils.hasText(token) || tenantId < 0) {
            return null;
        }
        return withTenantContext(tenantId, () -> SaOAuth2Util.getAccessToken(token));
    }

    private ClientTokenModel readClientTokenInTenant(long tenantId, String token) {
        if (!StringUtils.hasText(token) || tenantId < 0) {
            return null;
        }
        return withTenantContext(tenantId, () -> SaOAuth2Util.getClientToken(token));
    }

    private RefreshTokenModel readRefreshTokenInTenant(long tenantId, String refreshToken) {
        if (!StringUtils.hasText(refreshToken) || tenantId < 0) {
            return null;
        }
        return withTenantContext(tenantId, () -> SaOAuth2Util.getRefreshToken(refreshToken));
    }

    /**
     * 解析 refresh_token 对应的真实会话租户。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>后台 admin client 优先回退 tenant_id=0，兼容系统级管理员 refresh token。</li>
     *   <li>普通租户管理员和普通用户 token 继续停留在请求租户。</li>
     * </ul>
     */
    private long resolveRefreshSessionTenantId(long tenantId, String clientId, String refreshToken, SaClientModel clientModel) {
        if (!isAdminClient(clientModel)) {
            return tenantId;
        }
        RefreshTokenModel systemRefreshToken = readRefreshTokenInTenant(0L, refreshToken);
        if (isSystemAdminRefreshToken(tenantId, systemRefreshToken, clientId)) {
            if (log.isDebugEnabled()) {
                log.debug("refresh_token 命中系统级会话：requestTenantId={}, clientId={}, loginId={}",
                        tenantId,
                        safe(clientId),
                        systemRefreshToken.loginId);
            }
            return 0L;
        }
        return tenantId;
    }

    /**
     * 解析撤销 token 时应落在哪个会话租户。
     */
    private long resolveRevokeSessionTenantId(long tenantId, String clientId, String token, String tokenTypeHint, SaClientModel clientModel) {
        if (!isAdminClient(clientModel)) {
            return tenantId;
        }
        String normalizedHint = tokenTypeHint == null ? "" : tokenTypeHint.trim().toLowerCase();

        if (normalizedHint.isEmpty() || "access_token".equals(normalizedHint)) {
            AccessTokenModel systemAccessToken = readAccessTokenInTenant(0L, token);
            if (isSystemAdminAccessToken(tenantId, systemAccessToken)) {
                return 0L;
            }
        }
        if (normalizedHint.isEmpty() || "refresh_token".equals(normalizedHint)) {
            RefreshTokenModel systemRefreshToken = readRefreshTokenInTenant(0L, token);
            if (isSystemAdminRefreshToken(tenantId, systemRefreshToken, clientId)) {
                return 0L;
            }
        }
        return tenantId;
    }

    /**
     * 判断当前 client 是否属于后台管理员链路。
     */
    private boolean isAdminClient(SaClientModel clientModel) {
        if (clientModel == null) {
            return false;
        }
        return containsScope(clientModel.contractScope, "admin");
    }

    /**
     * 判断 access_token 是否属于系统级管理员会话。
     */
    private boolean isSystemAdminAccessToken(long requestTenantId, AccessTokenModel tokenModel) {
        if (tokenModel == null || !containsScope(tokenModel.scope, "admin")) {
            return false;
        }
        long adminId = parseUserId(tokenModel.loginId);
        if (adminId <= 0) {
            return false;
        }
        return adminAuthoritiesService.isTenantAllowed(requestTenantId, adminId);
    }

    /**
     * 判断 refresh_token 是否属于系统级管理员会话。
     */
    private boolean isSystemAdminRefreshToken(long requestTenantId, RefreshTokenModel tokenModel, String clientId) {
        if (tokenModel == null || !containsScope(tokenModel.scope, "admin")) {
            return false;
        }
        if (StringUtils.hasText(clientId) && !clientId.equals(tokenModel.clientId)) {
            return false;
        }
        long adminId = parseUserId(tokenModel.loginId);
        if (adminId <= 0) {
            return false;
        }
        return adminAuthoritiesService.isTenantAllowed(requestTenantId, adminId);
    }

    /**
     * 临时切换 OAuth 会话租户并在结束后恢复现场。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>Sa-Token OAuth2 的 Redis Key 会从 TenantContext 读取 tenantId。</li>
     *   <li>系统级管理员 token 固定落在 tenant_id=0，因此签发、刷新、自省、撤销都需要临时切换上下文。</li>
     * </ul>
     */
    private <T> T withTenantContext(long tenantId, Supplier<T> supplier) {
        Long previousTenantId = TenantContext.getTenantIdOrNull();
        try {
            TenantContext.setTenantId(tenantId);
            return supplier.get();
        } finally {
            if (previousTenantId == null) {
                TenantContext.clear();
            } else {
                TenantContext.setTenantId(previousTenantId);
            }
        }
    }

    private static long parseUserId(Object userId) {
        if (userId == null) {
            return -1;
        }
        try {
            return Long.parseLong(String.valueOf(userId).trim());
        } catch (Exception ignore) {
            return -1;
        }
    }

    private static String maskDevice(String deviceId) {
        if (!StringUtils.hasText(deviceId)) {
            return "";
        }
        String v = deviceId.trim();
        if (v.length() <= 8) {
            return v;
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    /**
     * 用户侧租户状态校验入口。
     */
    private void enforceTenantEnabledForUserRequest(long tenantId, String scene) {
        if (tenantStatusService == null) {
            return;
        }
        tenantStatusService.ensureTenantEnabledForUser(tenantId, scene);
    }


    private static String resolveScopeForRequest(String scope, String contractScope, UserPrincipal principal) {
        // 1) 兼容 OAuth2 标准：请求 scope 可能是空格分隔；Sa-Token 内部使用 CSV
        String requestedCsv = normalizeScopeToCsv(scope);
        String contractCsv = normalizeScopeToCsv(contractScope);

        // 2) 如果客户端请求未指定 scope，则按“签约 scope”作为默认（与当前骨架行为一致）
        String resolvedCsv = StringUtils.hasText(requestedCsv) ? requestedCsv : contractCsv;

        // 3) 预留：未来如果 user scopes 生效，可在这里做交集（当前 principal.scopes 为空）
        if (principal != null && principal.scopes() != null && !principal.scopes().isEmpty()) {
            Set<String> userScopes = principal.scopes();
            Set<String> req = Arrays.stream(resolvedCsv.split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .filter(userScopes::contains)
                    .collect(Collectors.toSet());
            return String.join(",", req);
        }
        return resolvedCsv;
    }

    private static String resolveScopeForClient(String scope, String contractScope) {
        String requestedCsv = normalizeScopeToCsv(scope);
        String contractCsv = normalizeScopeToCsv(contractScope);
        return StringUtils.hasText(requestedCsv) ? requestedCsv : contractCsv;
    }

    private static String normalizeScopeToCsv(String scope) {
        if (!StringUtils.hasText(scope)) {
            return "";
        }
        return Arrays.stream(scope.trim().split("[,\\s]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .collect(Collectors.joining(","));
    }

    private static String normalizeScopeToSpace(String scopeCsv) {
        if (!StringUtils.hasText(scopeCsv)) {
            return null;
        }
        return Arrays.stream(scopeCsv.trim().split("[,\\s]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .collect(Collectors.joining(" "));
    }

    private static boolean containsScope(String scopeCsvOrSpace, String target) {
        if (!StringUtils.hasText(scopeCsvOrSpace) || !StringUtils.hasText(target)) {
            return false;
        }
        String t = target.trim();
        if (t.isEmpty()) {
            return false;
        }
        return Arrays.stream(scopeCsvOrSpace.trim().split("[,\\s]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .anyMatch(s -> t.equalsIgnoreCase(s));
    }
}
