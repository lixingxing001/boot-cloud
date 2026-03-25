package com.bootcloud.auth.core.user;

import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.core.error.OAuthException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DevUserAuthenticator implements UserAuthenticator {

    private final boolean enabled;
    private final PasswordEncoder passwordEncoder;
    private final Map<String, AuthServerProperties.DevUserConfig> users = new HashMap<>();

    public DevUserAuthenticator(AuthServerProperties properties, PasswordEncoder passwordEncoder) {
        this.enabled = properties.isDevUsersEnabled();
        this.passwordEncoder = passwordEncoder;
        for (AuthServerProperties.DevUserConfig u : properties.getDevUsers()) {
            users.put(key(u.getTenantId(), u.getUsername()), u);
        }
    }

    @Override
    public UserPrincipal authenticatePassword(long tenantId, String username, String password) {
        if (!enabled) {
            throw OAuthException.invalidGrant("password grant is not enabled (devUsersEnabled=false)");
        }
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw OAuthException.invalidRequest("missing username or password");
        }
        AuthServerProperties.DevUserConfig u = users.get(key(tenantId, username));
        if (u == null || !u.isEnabled()) {
            throw OAuthException.invalidGrant("invalid username or password");
        }
        if (!passwordEncoder.matches(password, u.getPasswordHash())) {
            throw OAuthException.invalidGrant("invalid username or password");
        }
        Set<String> scopes = new HashSet<>();
        if (u.getScopes() != null) scopes.addAll(u.getScopes());
        return new UserPrincipal(u.getUserId(), scopes);
    }

    private static String key(long tenantId, String username) {
        return tenantId + ":" + (username == null ? "" : username.trim().toLowerCase());
    }
}

