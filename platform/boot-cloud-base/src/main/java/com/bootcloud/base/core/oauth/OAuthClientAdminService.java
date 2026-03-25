package com.bootcloud.base.core.oauth;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.bootcloud.base.infra.mybatis.entity.OAuthClientEntity;
import com.bootcloud.base.infra.mybatis.mapper.OAuthClientMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * OAuth2 Client 管理服务（boot-cloud-base）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该服务只管理表 <code>boot_cloud_oauth_client</code>，供 boot-cloud-auth 读取。</li>
 *   <li>重要：client_secret 只存 hash（BCrypt）。明文只在创建/重置时短暂出现。</li>
 * </ul>
 */
@Service
public class OAuthClientAdminService {

    private static final Logger log = LoggerFactory.getLogger(OAuthClientAdminService.class);
    private static final SecureRandom RNG = new SecureRandom();

    private final OAuthClientMapper clientMapper;
    private final PasswordEncoder passwordEncoder;

    public OAuthClientAdminService(OAuthClientMapper clientMapper, PasswordEncoder passwordEncoder) {
        this.clientMapper = clientMapper;
        this.passwordEncoder = passwordEncoder;
    }

    public IPage<OAuthClientEntity> page(long tenantId, String clientIdLike, Integer status, int pageNo, int pageSize) {
        LambdaQueryWrapper<OAuthClientEntity> qw = new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, tenantId)
                .orderByDesc(OAuthClientEntity::getId);
        if (StringUtils.hasText(clientIdLike)) {
            qw.like(OAuthClientEntity::getClientId, clientIdLike.trim());
        }
        if (status != null) {
            qw.eq(OAuthClientEntity::getStatus, status);
        }
        return clientMapper.selectPage(new Page<>(pageNo, pageSize), qw);
    }

    public OAuthClientEntity get(long tenantId, long id) {
        OAuthClientEntity e = clientMapper.selectById(id);
        if (e == null || e.getTenantId() == null || e.getTenantId() != tenantId) {
            return null;
        }
        return e;
    }

    @Transactional
    public OAuthClientEntity create(CreateCommand cmd) {
        long tenantId = cmd.tenantId;
        if (!StringUtils.hasText(cmd.clientId)) {
            throw new IllegalArgumentException("client_id is required");
        }
        if (!StringUtils.hasText(cmd.clientSecretPlain)) {
            throw new IllegalArgumentException("client_secret is required");
        }

        // 唯一约束：tenant_id + client_id
        OAuthClientEntity existed = clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, tenantId)
                .eq(OAuthClientEntity::getClientId, cmd.clientId.trim())
                .last("LIMIT 1"));
        if (existed != null) {
            throw new IllegalArgumentException("client_id already exists");
        }

        OAuthClientEntity e = new OAuthClientEntity();
        e.setTenantId(tenantId);
        e.setScopeType(resolveScopeType(tenantId));
        e.setClientId(cmd.clientId.trim());
        e.setClientSecret(hashSecret(cmd.clientSecretPlain.trim()));
        e.setClientName(StringUtils.hasText(cmd.clientName) ? cmd.clientName.trim() : null);
        e.setGrantTypes(normalizeCsvLower(cmd.grantTypes));
        e.setScopes(normalizeCsv(cmd.scopes));
        e.setRedirectUris(normalizeRedirectUris(cmd.redirectUris));
        e.setAccessTokenTtlSeconds(cmd.accessTokenTtlSeconds);
        e.setRefreshTokenTtlSeconds(cmd.refreshTokenTtlSeconds);
        e.setAllowRefreshToken(cmd.allowRefreshToken);
        e.setStatus(cmd.status);
        e.setRemark(StringUtils.hasText(cmd.remark) ? cmd.remark.trim() : null);

        clientMapper.insert(e);
        log.info("创建 OAuth client：tenantId={}, scopeType={}, clientId={}, id={}",
                tenantId, e.getScopeType(), e.getClientId(), e.getId());
        return e;
    }

    @Transactional
    public OAuthClientEntity update(UpdateCommand cmd) {
        OAuthClientEntity e = get(cmd.tenantId, cmd.id);
        if (e == null) {
            throw new IllegalArgumentException("client not found");
        }

        if (StringUtils.hasText(cmd.clientName)) {
            e.setClientName(cmd.clientName.trim());
        }
        e.setScopeType(resolveScopeType(e.getTenantId()));
        if (cmd.grantTypes != null) {
            e.setGrantTypes(normalizeCsvLower(cmd.grantTypes));
        }
        if (cmd.scopes != null) {
            e.setScopes(normalizeCsv(cmd.scopes));
        }
        if (cmd.redirectUris != null) {
            e.setRedirectUris(normalizeRedirectUris(cmd.redirectUris));
        }
        if (cmd.accessTokenTtlSeconds != null) {
            e.setAccessTokenTtlSeconds(cmd.accessTokenTtlSeconds);
        }
        if (cmd.refreshTokenTtlSeconds != null) {
            e.setRefreshTokenTtlSeconds(cmd.refreshTokenTtlSeconds);
        }
        if (cmd.allowRefreshToken != null) {
            e.setAllowRefreshToken(cmd.allowRefreshToken);
        }
        if (cmd.status != null) {
            e.setStatus(cmd.status);
        }
        if (cmd.remark != null) {
            e.setRemark(StringUtils.hasText(cmd.remark) ? cmd.remark.trim() : null);
        }

        clientMapper.updateById(e);
        log.info("更新 OAuth client：tenantId={}, scopeType={}, clientId={}, id={}",
                cmd.tenantId, e.getScopeType(), e.getClientId(), e.getId());
        return e;
    }

    @Transactional
    public ResetSecretResult resetSecret(long tenantId, long id, String newSecretPlain) {
        OAuthClientEntity e = get(tenantId, id);
        if (e == null) {
            throw new IllegalArgumentException("client not found");
        }

        String plain = StringUtils.hasText(newSecretPlain) ? newSecretPlain.trim() : randomSecret(32);
        e.setClientSecret(hashSecret(plain));
        clientMapper.updateById(e);
        log.info("重置 OAuth client_secret：tenantId={}, scopeType={}, clientId={}, id={}",
                tenantId, e.getScopeType(), e.getClientId(), e.getId());

        // 说明：明文只在该响应中出现一次，调用方应自行保存
        return new ResetSecretResult(e.getId(), e.getClientId(), plain);
    }

    /**
     * 硬删除 OAuth client（物理删除）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该操作不可逆，建议先在管理界面/脚本层面做二次确认。</li>
     *   <li>tenantId 必须匹配；避免跨租户误删。</li>
     * </ul>
     */
    @Transactional
    public void delete(long tenantId, long id) {
        OAuthClientEntity e = get(tenantId, id);
        if (e == null) {
            throw new IllegalArgumentException("client not found");
        }

        int rows = clientMapper.delete(new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, tenantId)
                .eq(OAuthClientEntity::getId, id));
        if (rows <= 0) {
            // 理论上不应发生（前面已 get 成功），但保留兜底日志，方便排查并发删除等问题
            log.warn("删除 OAuth client 失败：rows=0，tenantId={}, clientId={}, id={}", tenantId, e.getClientId(), id);
            throw new IllegalArgumentException("client not found");
        }
        log.info("删除 OAuth client：tenantId={}, clientId={}, id={}", tenantId, e.getClientId(), id);
    }

    private String hashSecret(String plain) {
        // 支持 {public}：用于 public client（必须 PKCE）。该值本身不做 BCrypt。
        if ("{public}".equals(plain)) {
            return "{public}";
        }
        return passwordEncoder.encode(plain);
    }

    private static String randomSecret(int bytes) {
        byte[] b = new byte[bytes];
        RNG.nextBytes(b);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String normalizeCsvLower(String raw) {
        String csv = normalizeCsv(raw);
        if (!StringUtils.hasText(csv)) return "";
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .map(String::toLowerCase)
                .distinct()
                .collect(Collectors.joining(","));
    }

    private static String normalizeCsv(String raw) {
        if (!StringUtils.hasText(raw)) {
            return "";
        }
        return Arrays.stream(raw.trim().split("[,\\s]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .collect(Collectors.joining(","));
    }

    private static String normalizeRedirectUris(List<String> redirectUris) {
        if (redirectUris == null) {
            return null;
        }
        List<String> list = redirectUris.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (list.isEmpty()) {
            return "";
        }
        // 统一存 JSON 数组字符串，避免 URL 中的逗号/空格导致 CSV 解析歧义
        String quoted = list.stream()
                .map(s -> "\"" + s.replace("\"", "\\\"") + "\"")
                .collect(Collectors.joining(","));
        return "[" + quoted + "]";
    }

    public record ResetSecretResult(long id, String clientId, String clientSecret) {
    }

    public static class CreateCommand {
        public long tenantId;
        public String clientId;
        public String clientSecretPlain;
        public String clientName;
        public String grantTypes;
        public String scopes;
        public List<String> redirectUris;
        public Integer accessTokenTtlSeconds;
        public Integer refreshTokenTtlSeconds;
        public Integer allowRefreshToken;
        public Integer status;
        public String remark;
    }

    public static class UpdateCommand {
        public long tenantId;
        public long id;
        public String clientName;
        public String grantTypes;
        public String scopes;
        public List<String> redirectUris;
        public Integer accessTokenTtlSeconds;
        public Integer refreshTokenTtlSeconds;
        public Integer allowRefreshToken;
        public Integer status;
        public String remark;
    }

    /**
     * 说明：
     * 统一根据 tenantId 推导 client 作用域，避免不同写入口各自拼魔法值。
     */
    public static String resolveScopeType(Long tenantId) {
        return tenantId != null && tenantId == OAuthClientEntity.SYSTEM_TENANT_ID
                ? OAuthClientEntity.SCOPE_TYPE_SYSTEM
                : OAuthClientEntity.SCOPE_TYPE_TENANT;
    }
}
