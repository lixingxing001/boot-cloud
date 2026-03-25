package com.bootcloud.auth.core.admin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.infra.mybatis.entity.AdminAuthUserEntity;
import com.bootcloud.auth.infra.mybatis.mapper.AdminAuthUserMapper;
import com.bootcloud.auth.infra.mybatis.mapper.AdminPermissionMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 管理员权限点服务（用于 OAuth2 自省回填 authorities）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该服务用于把后台权限点带到 OAuth2 自省结果里，便于后台服务资源服务化。</li>
 *   <li>为了避免每次自省都查库，这里对权限结果做短缓存（Redis）。</li>
 * </ul>
 */
@Slf4j
@Service
public class AdminAuthoritiesService {

    /**
     * 说明：
     * 这里升级一个缓存版本号，避免旧缓存里还残留不完整的 authority 结果。
     */
    private static final String PREFIX = "auth:admin:authorities:v3:";
    private static final String SUPER_ADMIN_AUTHORITY = "super_admin";

    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final AdminAuthUserMapper adminAuthUserMapper;
    private final AdminPermissionMapper permissionMapper;
    private final AuthServerProperties properties;

    public AdminAuthoritiesService(
            StringRedisTemplate redis,
            ObjectMapper mapper,
            AdminAuthUserMapper adminAuthUserMapper,
            AdminPermissionMapper permissionMapper,
            AuthServerProperties properties
    ) {
        this.redis = redis;
        this.mapper = mapper;
        this.adminAuthUserMapper = adminAuthUserMapper;
        this.permissionMapper = permissionMapper;
        this.properties = properties;
    }

    /**
     * 校验当前 tenantId 是否允许承载该管理员 token。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>SYSTEM 管理员允许在任意租户头下被自省通过。</li>
     *   <li>TENANT 管理员必须与请求 tenantId 一致。</li>
     * </ul>
     */
    public boolean isTenantAllowed(long tenantId, long adminId) {
        if (tenantId <= 0 || adminId <= 0) {
            return false;
        }
        if (isCompatibleSuperAdmin(adminId)) {
            if (log.isDebugEnabled()) {
                log.debug("管理员租户承载校验通过：命中 super_admin 角色，tenantId={}, adminId={}", tenantId, adminId);
            }
            return true;
        }
        AdminAuthUserEntity admin = adminAuthUserMapper.selectById(adminId);
        if (admin == null || admin.getId() == null) {
            return false;
        }
        if (admin.getDeleted() != null && admin.getDeleted() != 0) {
            return false;
        }
        if (admin.getStatus() == null || admin.getStatus() != 1) {
            return false;
        }
        if ("SYSTEM".equalsIgnoreCase(admin.getScopeType())) {
            return admin.getTenantId() != null && admin.getTenantId() == 0L;
        }
        return "TENANT".equalsIgnoreCase(admin.getScopeType())
                && admin.getTenantId() != null
                && admin.getTenantId() == tenantId;
    }

    public List<String> getAuthorities(long tenantId, long adminId) {
        if (tenantId <= 0 || adminId <= 0) {
            return Collections.emptyList();
        }
        if (!isTenantAllowed(tenantId, adminId)) {
            log.warn("管理员 token 租户校验失败，拒绝回填 authorities：tenantId={}, adminId={}", tenantId, adminId);
            return Collections.emptyList();
        }

        Duration ttl = Duration.ofSeconds(Math.max(5, properties.getAdminAuthorities().getCacheTtlSeconds()));
        String key = PREFIX + tenantId + ":" + adminId;

        try {
            String cached = redis.opsForValue().get(key);
            if (StringUtils.hasText(cached)) {
                return mapper.readValue(cached, new TypeReference<List<String>>() {});
            }
        } catch (Exception e) {
            // 说明：缓存读失败不影响主流程，降级查库
            log.debug("读取管理员权限缓存失败，降级查库：adminId={}, err={}", adminId, e.getMessage());
        }

        List<String> perms = mergeAuthorities(adminId, tenantId);

        try {
            redis.opsForValue().set(key, mapper.writeValueAsString(perms), ttl);
        } catch (Exception e) {
            // 说明：缓存写失败不影响主流程
            log.debug("写入管理员权限缓存失败：adminId={}, err={}", adminId, e.getMessage());
        }

        return perms;
    }

    /**
     * 说明：
     * 权限合并规则现在分两层：
     * 1. 系统级 super_admin 角色直接注入 super_admin authority。
     * 2. 继续保留基于 t_admin_menu.permission 的权限点映射。
     */
    private List<String> mergeAuthorities(long adminId, long tenantId) {
        Set<String> authoritySet = new LinkedHashSet<>();

        if (isCompatibleSuperAdmin(adminId)) {
            authoritySet.add(SUPER_ADMIN_AUTHORITY);
            if (log.isDebugEnabled()) {
                log.debug("管理员 authority 直接注入 super_admin：tenantId={}, adminId={}", tenantId, adminId);
            }
        }

        List<String> menuPermissions = permissionMapper.selectPermissionsByAdminId(adminId, tenantId);
        if (menuPermissions != null && !menuPermissions.isEmpty()) {
            for (String permission : menuPermissions) {
                if (StringUtils.hasText(permission)) {
                    authoritySet.add(permission.trim());
                }
            }
        }

        if (authoritySet.isEmpty()) {
            return Collections.emptyList();
        }
        return new ArrayList<>(authoritySet);
    }

    /**
     * 判断管理员是否属于 super_admin 身份。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>这里把 super_admin 视为平台级最高权限角色。</li>
     *   <li>即便后台账号数据仍在演进中，也允许继续按系统级管理员使用。</li>
     * </ul>
     */
    private boolean isCompatibleSuperAdmin(long adminId) {
        return permissionMapper.countCompatibleSuperAdminByAdminId(adminId) > 0;
    }
}
