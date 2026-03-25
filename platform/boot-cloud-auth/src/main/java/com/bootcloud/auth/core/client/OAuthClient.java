package com.bootcloud.auth.core.client;

import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.core.error.OAuthException;
import lombok.Getter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Getter
public class OAuthClient {

    private final long tenantId;
    private final String clientId;
    private final String clientSecretHash;
    private final Set<String> grantTypes;
    private final Set<String> scopes;
    private final List<String> redirectUris;
    private final Long accessTokenTtlSeconds;
    private final Long refreshTokenTtlSeconds;
    private final Boolean allowRefreshToken;
    private final boolean enabled;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    private OAuthClient(
            long tenantId,
            String clientId,
            String clientSecretHash,
            Set<String> grantTypes,
            Set<String> scopes,
            List<String> redirectUris,
            Long accessTokenTtlSeconds,
            Long refreshTokenTtlSeconds,
            Boolean allowRefreshToken,
            boolean enabled
    ) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.grantTypes = grantTypes;
        this.scopes = scopes;
        this.redirectUris = redirectUris;
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
        this.allowRefreshToken = allowRefreshToken;
        this.enabled = enabled;
    }

    /**
     * 用于从数据库/配置构造 OAuthClient 的工厂方法。
     *
     * <p>注意：不要在其它模块直接 new 本类，统一通过工厂方法构造，方便后续扩展字段时统一收口。</p>
     */
    public static OAuthClient of(
            long tenantId,
            String clientId,
            String clientSecretHash,
            Set<String> grantTypes,
            Set<String> scopes,
            List<String> redirectUris,
            Long accessTokenTtlSeconds,
            Long refreshTokenTtlSeconds,
            Boolean allowRefreshToken,
            boolean enabled
    ) {
        return new OAuthClient(
                tenantId,
                clientId,
                clientSecretHash,
                grantTypes,
                scopes,
                redirectUris,
                accessTokenTtlSeconds,
                refreshTokenTtlSeconds,
                allowRefreshToken,
                enabled
        );
    }

    public static OAuthClient fromConfig(AuthServerProperties.ClientConfig cfg) {
        Set<String> gts = new HashSet<>();
        for (String s : cfg.getGrantTypes()) {
            if (StringUtils.hasText(s)) gts.add(s.trim().toLowerCase());
        }
        Set<String> sc = new HashSet<>();
        for (String s : cfg.getScopes()) {
            if (StringUtils.hasText(s)) sc.add(s.trim());
        }
        List<String> ru = cfg.getRedirectUris() == null ? List.of() : cfg.getRedirectUris().stream().filter(StringUtils::hasText).map(String::trim).toList();
        return new OAuthClient(
                cfg.getTenantId(),
                cfg.getClientId(),
                cfg.getClientSecretHash(),
                Collections.unmodifiableSet(gts),
                Collections.unmodifiableSet(sc),
                List.copyOf(ru),
                cfg.getAccessTokenTtlSeconds(),
                cfg.getRefreshTokenTtlSeconds(),
                cfg.getAllowRefreshToken(),
                cfg.isEnabled()
        );
    }

    public void verifySecret(String clientSecret) {
        if (!StringUtils.hasText(clientSecretHash)) {
            throw OAuthException.invalidClient("client_secret not configured");
        }
        if (!StringUtils.hasText(clientSecret)) {
            throw OAuthException.invalidClient("missing client_secret");
        }
        if (!encoder.matches(clientSecret, clientSecretHash)) {
            throw OAuthException.invalidClient("invalid client_secret");
        }
    }

    public void requireGrant(String grantType) {
        if (!grantTypes.contains(grantType)) {
            throw OAuthException.unauthorizedClient("grant not allowed: " + grantType);
        }
    }

    public void validateRedirectUri(String redirectUri) {
        if (!StringUtils.hasText(redirectUri)) {
            throw OAuthException.invalidRequest("missing redirect_uri");
        }
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw OAuthException.invalidRequest("client redirect_uris not configured");
        }
        if (!redirectUris.contains(redirectUri)) {
            throw OAuthException.invalidRequest("redirect_uri not allowed");
        }
    }

    public Set<String> resolveScopes(String requestedScope, Set<String> subjectScopes) {
        Set<String> requested = new HashSet<>();
        if (StringUtils.hasText(requestedScope)) {
            for (String s : requestedScope.split("[,\\s]+")) {
                if (StringUtils.hasText(s)) requested.add(s.trim());
            }
        }
        if (requested.isEmpty()) {
            return scopes;
        }
        if (!scopes.containsAll(requested)) {
            throw OAuthException.invalidScope("requested scope not allowed");
        }
        if (subjectScopes != null && !subjectScopes.isEmpty()) {
            if (!subjectScopes.containsAll(requested)) {
                throw OAuthException.invalidScope("requested scope not allowed for user");
            }
        }
        return Collections.unmodifiableSet(requested);
    }

    public String buildRedirectUrl(String redirectUri, String code, String state) {
        StringBuilder sb = new StringBuilder(redirectUri);
        sb.append(redirectUri.contains("?") ? "&" : "?");
        sb.append("code=").append(url(code));
        if (StringUtils.hasText(state)) {
            sb.append("&state=").append(url(state));
        }
        return sb.toString();
    }

    private static String url(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
