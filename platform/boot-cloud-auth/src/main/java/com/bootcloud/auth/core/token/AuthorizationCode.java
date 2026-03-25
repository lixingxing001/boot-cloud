package com.bootcloud.auth.core.token;

import java.time.Instant;
import java.util.Set;

public record AuthorizationCode(
        long tenantId,
        String code,
        String clientId,
        String userId,
        String redirectUri,
        Set<String> scopes,
        Instant expiresAt
) {
}

