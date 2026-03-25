package com.bootcloud.auth.core.client;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.bootcloud.auth.core.error.OAuthException;
import com.bootcloud.auth.infra.mybatis.entity.OAuthClientEntity;
import com.bootcloud.auth.infra.mybatis.mapper.OAuthClientMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 从数据库读取 OAuth2 client（多租户）。
 *
 * <p>实现说明：</p>
 * <ul>
 *   <li>client 存储在 {@code boot_cloud_oauth_client} 表，tenant 维度隔离。</li>
 *   <li>client_secret 建议存 BCrypt 哈希（SQL 文件中已提示）。</li>
 * </ul>
 */
public class DbClientRegistry implements ClientRegistry {

    private final OAuthClientMapper clientMapper;
    private final PasswordEncoder passwordEncoder;

    public DbClientRegistry(OAuthClientMapper clientMapper, PasswordEncoder passwordEncoder) {
        this.clientMapper = clientMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public OAuthClient findClient(long tenantId, String clientId) {
        if (tenantId < 0 || !StringUtils.hasText(clientId)) {
            return null;
        }

        OAuthClientEntity e = tenantId == OAuthClientEntity.SYSTEM_TENANT_ID
                ? selectSystemScopedClient(clientId)
                : selectTenantScopedClient(tenantId, clientId);
        if (e == null && tenantId != OAuthClientEntity.SYSTEM_TENANT_ID) {
            e = selectSystemScopedClient(clientId);
        }
        if (e == null) {
            return null;
        }
        return map(e);
    }

    /**
     * 说明：
     * 业务租户优先查租户级 client，保留未来按租户覆写 OAuth 参数的能力。
     */
    private OAuthClientEntity selectTenantScopedClient(long tenantId, String clientId) {
        return clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, tenantId)
                .eq(OAuthClientEntity::getClientId, clientId)
                .eq(OAuthClientEntity::getStatus, 1)
                .and(w -> w.isNull(OAuthClientEntity::getScopeType)
                        .or()
                        .eq(OAuthClientEntity::getScopeType, OAuthClientEntity.SCOPE_TYPE_TENANT))
                .last("LIMIT 1"));
    }

    /**
     * 说明：
     * 平台基础设施类 client 允许走系统级 fallback，避免默认租户切换影响网关、自省等基础链路。
     */
    private OAuthClientEntity selectSystemScopedClient(String clientId) {
        return clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, OAuthClientEntity.SYSTEM_TENANT_ID)
                .eq(OAuthClientEntity::getScopeType, OAuthClientEntity.SCOPE_TYPE_SYSTEM)
                .eq(OAuthClientEntity::getClientId, clientId)
                .eq(OAuthClientEntity::getStatus, 1)
                .last("LIMIT 1"));
    }

    private OAuthClient map(OAuthClientEntity e) {
        long tenantId = e.getTenantId() == null ? 0 : e.getTenantId();
        if (tenantId < 0) {
            throw OAuthException.invalidClient("client tenant_id is invalid");
        }

        Set<String> grantTypes = splitCsvLower(e.getGrantTypes());
        Set<String> scopes = splitCsv(e.getScopes());
        List<String> redirectUris = parseRedirectUris(e.getRedirectUris());

        // client_secret 允许直接存 BCrypt 哈希或明文（仅用于过渡；生产建议只存 hash）
        String secret = e.getClientSecret();
        String secretHash = secret;
        if (StringUtils.hasText(secret) && !secret.startsWith("$2a$") && !secret.startsWith("$2b$") && !secret.startsWith("$2y$")) {
            // 明文 -> hash（仅内存中转换，不回写 DB）
            secretHash = passwordEncoder.encode(secret);
        }

        return OAuthClient.of(
                tenantId,
                e.getClientId(),
                secretHash,
                grantTypes,
                scopes,
                redirectUris,
                e.getAccessTokenTtlSeconds() == null ? null : e.getAccessTokenTtlSeconds().longValue(),
                e.getRefreshTokenTtlSeconds() == null ? null : e.getRefreshTokenTtlSeconds().longValue(),
                e.getAllowRefreshToken() == null ? null : e.getAllowRefreshToken() == 1,
                e.getStatus() != null && e.getStatus() == 1
        );
    }

    private static Set<String> splitCsvLower(String csv) {
        return split(csv).stream().map(s -> s.toLowerCase()).collect(Collectors.toSet());
    }

    private static Set<String> splitCsv(String csv) {
        return split(csv).stream().collect(Collectors.toSet());
    }

    private static List<String> split(String csv) {
        if (!StringUtils.hasText(csv)) {
            return List.of();
        }
        return Arrays.stream(csv.split("[,\\s]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }

    private static List<String> parseRedirectUris(String raw) {
        if (!StringUtils.hasText(raw)) {
            return List.of();
        }
        String s = raw.trim();

        // 允许 JSON 数组（例如 ["https://a/cb","https://b/cb"]），这里先做非常轻量的解析
        if (s.startsWith("[") && s.endsWith("]")) {
            String inner = s.substring(1, s.length() - 1).trim();
            if (inner.isEmpty()) return List.of();
            return Arrays.stream(inner.split(","))
                    .map(String::trim)
                    .map(v -> v.replaceAll("^\"|\"$", ""))
                    .filter(StringUtils::hasText)
                    .toList();
        }
        return split(s);
    }
}
