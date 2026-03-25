package com.bootcloud.auth.core.token;

import com.bootcloud.auth.core.client.OAuthClient;
import com.bootcloud.auth.core.dto.TokenResponse;

import java.time.Instant;
import java.util.Set;

public interface OAuthTokenStore {

    AuthorizationCode createAuthorizationCode(long tenantId, String clientId, String userId, String redirectUri, Set<String> scopes);

    AuthorizationCode consumeAuthorizationCode(long tenantId, String code);

    OAuthAccessToken issueAccessToken(long tenantId, String clientId, String userId, String subjectType, Set<String> scopes, Long ttlSeconds);

    TokenResponse issueRefreshTokenIfAllowed(long tenantId, OAuthClient client, OAuthAccessToken accessToken);

    TokenResponse refreshAccessToken(long tenantId, OAuthClient client, String refreshToken, Instant now);

    OAuthAccessToken readAccessToken(long tenantId, String token);

    boolean revokeToken(long tenantId, String token, String tokenTypeHint);
}
