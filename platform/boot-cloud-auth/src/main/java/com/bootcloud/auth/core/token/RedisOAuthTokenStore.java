package com.bootcloud.auth.core.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.core.client.OAuthClient;
import com.bootcloud.auth.core.dto.TokenResponse;
import com.bootcloud.auth.core.error.OAuthException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;

@Component
public class RedisOAuthTokenStore implements OAuthTokenStore {

    private static final String PREFIX_AT = "auth:at:";
    private static final String PREFIX_RT = "auth:rt:";
    private static final String PREFIX_CODE = "auth:code:";

    private static final SecureRandom RNG = new SecureRandom();

    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final AuthServerProperties properties;

    public RedisOAuthTokenStore(StringRedisTemplate redis, ObjectMapper mapper, AuthServerProperties properties) {
        this.redis = redis;
        this.mapper = mapper;
        this.properties = properties;
    }

    @Override
    public AuthorizationCode createAuthorizationCode(long tenantId, String clientId, String userId, String redirectUri, Set<String> scopes) {
        String code = randomToken(32);
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.getAuthorizationCodeTtlSeconds());
        AuthorizationCode ac = new AuthorizationCode(tenantId, code, clientId, userId, redirectUri, scopes, exp);
        writeJson(keyCode(tenantId, code), ac, Duration.ofSeconds(properties.getAuthorizationCodeTtlSeconds()));
        return ac;
    }

    @Override
    public AuthorizationCode consumeAuthorizationCode(long tenantId, String code) {
        if (!StringUtils.hasText(code)) {
            return null;
        }
        String key = keyCode(tenantId, code);
        String json = redis.opsForValue().get(key);
        if (!StringUtils.hasText(json)) {
            return null;
        }
        redis.delete(key);
        return readJson(json, AuthorizationCode.class);
    }

    @Override
    public OAuthAccessToken issueAccessToken(long tenantId, String clientId, String userId, String subjectType, Set<String> scopes, Long ttlSeconds) {
        String token = randomToken(32);
        Instant now = Instant.now();
        long ttl = (ttlSeconds != null && ttlSeconds > 0) ? ttlSeconds : properties.getDefaultAccessTokenTtlSeconds();
        Instant exp = now.plusSeconds(ttl);
        OAuthAccessToken at = new OAuthAccessToken(tenantId, token, clientId, subjectType, userId, scopes, now, exp);
        writeJson(keyAccessToken(tenantId, token), at, Duration.ofSeconds(ttl));
        return at;
    }

    @Override
    public TokenResponse issueRefreshTokenIfAllowed(long tenantId, OAuthClient client, OAuthAccessToken accessToken) {
        boolean allow = client.getAllowRefreshToken() == null ? true : client.getAllowRefreshToken();
        if (!allow) {
            return TokenResponse.of(accessToken.token(), Duration.between(Instant.now(), accessToken.expiresAt()).toSeconds(), null, String.join(" ", accessToken.scopes()));
        }
        long rtTtl = client.getRefreshTokenTtlSeconds() == null ? properties.getDefaultRefreshTokenTtlSeconds() : client.getRefreshTokenTtlSeconds();
        String rt = randomToken(40);
        Instant now = Instant.now();
        OAuthRefreshToken refreshToken = new OAuthRefreshToken(
                tenantId,
                rt,
                client.getClientId(),
                accessToken.subjectType(),
                accessToken.userId(),
                accessToken.token(),
                accessToken.scopes(),
                now,
                now.plusSeconds(rtTtl)
        );
        writeJson(keyRefreshToken(tenantId, rt), refreshToken, Duration.ofSeconds(rtTtl));
        long expiresIn = Duration.between(now, accessToken.expiresAt()).toSeconds();
        String scope = accessToken.scopes() == null ? "" : String.join(" ", accessToken.scopes());
        return TokenResponse.of(accessToken.token(), expiresIn, rt, scope);
    }

    @Override
    public TokenResponse refreshAccessToken(long tenantId, OAuthClient client, String refreshToken, Instant now) {
        OAuthRefreshToken rt = readRefreshToken(tenantId, refreshToken);
        if (rt == null) {
            throw OAuthException.invalidGrant("invalid refresh_token");
        }
        if (!client.getClientId().equals(rt.clientId())) {
            throw OAuthException.invalidGrant("refresh_token does not belong to client");
        }
        if (!tenantIdEquals(tenantId, rt.tenantId())) {
            throw OAuthException.invalidGrant("refresh_token tenant mismatch");
        }

        OAuthAccessToken at = issueAccessToken(tenantId, client.getClientId(), rt.userId(), rt.subjectType(), rt.scopes(), client.getAccessTokenTtlSeconds());
        if (properties.isReuseRefreshToken()) {
            OAuthRefreshToken updated = new OAuthRefreshToken(
                    rt.tenantId(),
                    rt.token(),
                    rt.clientId(),
                    rt.subjectType(),
                    rt.userId(),
                    at.token(),
                    rt.scopes(),
                    rt.issuedAt(),
                    rt.expiresAt()
            );
            long ttl = Duration.between(now, rt.expiresAt()).toSeconds();
            writeJson(keyRefreshToken(tenantId, rt.token()), updated, Duration.ofSeconds(Math.max(ttl, 1)));
            long expiresIn = Duration.between(Instant.now(), at.expiresAt()).toSeconds();
            String scope = rt.scopes() == null ? "" : String.join(" ", rt.scopes());
            return TokenResponse.of(at.token(), expiresIn, rt.token(), scope);
        }

        redis.delete(keyRefreshToken(tenantId, rt.token()));
        return issueRefreshTokenIfAllowed(tenantId, client, at);
    }

    @Override
    public OAuthAccessToken readAccessToken(long tenantId, String token) {
        if (!StringUtils.hasText(token)) {
            return null;
        }
        String json = redis.opsForValue().get(keyAccessToken(tenantId, token));
        if (!StringUtils.hasText(json)) {
            return null;
        }
        return readJson(json, OAuthAccessToken.class);
    }

    @Override
    public boolean revokeToken(long tenantId, String token, String tokenTypeHint) {
        if (!StringUtils.hasText(token)) {
            return false;
        }
        String hint = tokenTypeHint == null ? "" : tokenTypeHint.trim().toLowerCase();
        boolean revoked = false;
        if (hint.isEmpty() || "access_token".equals(hint)) {
            revoked = revoked | Boolean.TRUE.equals(redis.delete(keyAccessToken(tenantId, token)));
        }
        if (hint.isEmpty() || "refresh_token".equals(hint)) {
            revoked = revoked | Boolean.TRUE.equals(redis.delete(keyRefreshToken(tenantId, token)));
        }
        return revoked;
    }

    private OAuthRefreshToken readRefreshToken(long tenantId, String refreshToken) {
        String json = redis.opsForValue().get(keyRefreshToken(tenantId, refreshToken));
        if (!StringUtils.hasText(json)) {
            return null;
        }
        return readJson(json, OAuthRefreshToken.class);
    }

    private void writeJson(String key, Object value, Duration ttl) {
        try {
            redis.opsForValue().set(key, mapper.writeValueAsString(value), ttl);
        } catch (JsonProcessingException e) {
            throw OAuthException.serverError("token_store_json_serialize_failed");
        }
    }

    private <T> T readJson(String json, Class<T> clazz) {
        try {
            return mapper.readValue(json, clazz);
        } catch (Exception e) {
            throw OAuthException.serverError("token_store_json_deserialize_failed");
        }
    }

    private static String randomToken(int bytes) {
        byte[] b = new byte[bytes];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static boolean tenantIdEquals(long t1, long t2) {
        return t1 == t2;
    }

    private static String keyAccessToken(long tenantId, String token) {
        return PREFIX_AT + tenantId + ":" + token;
    }

    private static String keyRefreshToken(long tenantId, String token) {
        return PREFIX_RT + tenantId + ":" + token;
    }

    private static String keyCode(long tenantId, String code) {
        return PREFIX_CODE + tenantId + ":" + code;
    }
}
