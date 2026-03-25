package com.bootcloud.gateway.core.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 说明：
 * 后台租户路由矩阵回归测试，防止路径与视角判断回归。
 */
class AdminTenantRoutingPolicyTest {

    private final AdminTenantRoutingPolicy policy = new AdminTenantRoutingPolicy();

    @Test
    void shouldReturnNonAdminDecisionWhenPathIsNotAdmin() {
        AdminTenantRoutingPolicy.Decision decision = policy.decide("/api/web/auth/password/token", new HttpHeaders());
        assertFalse(decision.adminPath());
        assertFalse(decision.forceRuntimeTenant());
        assertNull(decision.adminViewTenantId());
    }

    @Test
    void shouldNotForceRuntimeForAdminAuthPath() {
        AdminTenantRoutingPolicy.Decision decision = policy.decide("/api/web/admin/auth/password/token", new HttpHeaders());
        assertTrue(decision.adminPath());
        assertTrue(decision.adminAuthPath());
        assertFalse(decision.forceRuntimeTenant());
    }

    @Test
    void shouldNotForceRuntimeForAdminSystemView() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(AdminTenantRoutingPolicy.ADMIN_VIEW_MODE_HEADER, "system");

        AdminTenantRoutingPolicy.Decision decision = policy.decide("/api/admin/info", headers);
        assertTrue(decision.adminPath());
        assertTrue(decision.adminSystemView());
        assertFalse(decision.forceRuntimeTenant());
    }

    @Test
    void shouldResolveAdminViewTenantForTenantMode() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(AdminTenantRoutingPolicy.ADMIN_VIEW_MODE_HEADER, "tenant");
        headers.add(AdminTenantRoutingPolicy.ADMIN_VIEW_TENANT_HEADER, "6");

        AdminTenantRoutingPolicy.Decision decision = policy.decide("/api/admin/menus", headers);
        assertTrue(decision.adminTenantView());
        assertEquals(6L, decision.adminViewTenantId());
        assertFalse(decision.forceRuntimeTenant());
    }

    @Test
    void shouldForceRuntimeWhenTenantModeMissingTenantId() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(AdminTenantRoutingPolicy.ADMIN_VIEW_MODE_HEADER, "tenant");

        AdminTenantRoutingPolicy.Decision decision = policy.decide("/api/admin/menus", headers);
        assertTrue(decision.adminTenantView());
        assertNull(decision.adminViewTenantId());
        assertTrue(decision.forceRuntimeTenant());
    }

    @Test
    void shouldForceRuntimeForAdminPathWithoutMode() {
        AdminTenantRoutingPolicy.Decision decision = policy.decide("/api/admin/config", new HttpHeaders());
        assertTrue(decision.adminPath());
        assertTrue(decision.forceRuntimeTenant());
    }
}
