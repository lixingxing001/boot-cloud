package com.bootcloud.auth.core.token;

import java.time.Instant;
import java.util.Set;

public record OAuthRefreshToken(
        long tenantId,
        String token,
        String clientId,
        String subjectType,
        String userId,
        String accessToken,
        Set<String> scopes,
        Instant issuedAt,
        Instant expiresAt
) {
}
