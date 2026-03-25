package com.bootcloud.auth.core.tenant;

import com.bootcloud.auth.core.error.OAuthException;
import com.bootcloud.auth.infra.mybatis.entity.AuthTenantEntity;
import com.bootcloud.auth.infra.mybatis.mapper.AuthTenantMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * 租户启用状态校验服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>仅在用户侧认证链路执行启用状态校验。</li>
 *   <li>管理端 super_admin 视角不受租户 status=0 影响。</li>
 * </ul>
 */
@Slf4j
@Service
public class TenantStatusService {

    private final AuthTenantMapper evmTenantMapper;

    public TenantStatusService(AuthTenantMapper evmTenantMapper) {
        this.evmTenantMapper = evmTenantMapper;
    }

    /**
     * 断言“用户侧租户可用”。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>租户不存在或 status=0 都按不可用处理。</li>
     *   <li>命中不可用时抛出统一 OAuth 语义，便于网关/BFF/前端收口到 tenant_disabled。</li>
     * </ul>
     */
    public void ensureTenantEnabledForUser(long tenantId, String scene) {
        if (tenantId <= 0) {
            return;
        }
        AuthTenantEntity tenant = evmTenantMapper.selectById(tenantId);
        if (tenant == null) {
            log.warn("用户侧租户校验失败：租户不存在，scene={}, tenantId={}", safe(scene), tenantId);
            throw OAuthException.invalidRequest("tenant is disabled");
        }
        Integer status = tenant.getStatus();
        if (status == null || status != 1) {
            log.warn("用户侧租户校验失败：租户已禁用，scene={}, tenantId={}, status={}", safe(scene), tenantId, status);
            throw OAuthException.invalidRequest("tenant is disabled");
        }
        if (log.isDebugEnabled()) {
            log.debug("用户侧租户校验通过：scene={}, tenantId={}", safe(scene), tenantId);
        }
    }

    private static String safe(String raw) {
        return raw == null ? "" : raw.trim();
    }
}
