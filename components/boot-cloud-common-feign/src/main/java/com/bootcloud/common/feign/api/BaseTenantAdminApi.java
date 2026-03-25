package com.bootcloud.common.feign.api;

import com.bootcloud.common.feign.dto.base.BaseDefaultTenantUpdateRequest;
import com.bootcloud.common.feign.dto.base.BaseApiScopeRuleConfigUpdateRequest;
import com.bootcloud.common.feign.dto.base.BaseSecurityPublicPathsConfigUpdateRequest;
import com.bootcloud.common.feign.dto.base.BaseTenantUpsertRequest;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * boot-cloud-base 租户与域名内部管理接口（供后台系统设置调用）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>返回值统一使用 String，调用方自行按统一 ApiResponse 结构解析。</li>
 *   <li>接口路径都在 /internal/admin/**，调用时需携带内部鉴权头。</li>
 * </ul>
 */
public interface BaseTenantAdminApi {

    @GetMapping("/internal/admin/tenants")
    String pageTenants(@RequestParam Map<String, Object> params);

    @GetMapping("/internal/admin/tenants/{id}")
    String getTenant(@PathVariable("id") long id);

    @PostMapping("/internal/admin/tenants")
    String createTenant(@RequestBody BaseTenantUpsertRequest body);

    @PutMapping("/internal/admin/tenants/{id}")
    String updateTenant(@PathVariable("id") long id, @RequestBody BaseTenantUpsertRequest body);

    @DeleteMapping("/internal/admin/tenants/{id}")
    String deleteTenant(@PathVariable("id") long id);

    /**
     * 查询当前平台默认租户配置。
     */
    @GetMapping("/internal/admin/tenants/default")
    String getDefaultTenantConfig();

    /**
     * 更新当前平台默认租户配置。
     */
    @PutMapping("/internal/admin/tenants/default")
    String updateDefaultTenantConfig(@RequestBody BaseDefaultTenantUpdateRequest body);

    @GetMapping("/internal/admin/tenant-domains")
    String pageTenantDomains(@RequestParam Map<String, Object> params);

    @GetMapping("/internal/admin/tenant-domains/{id}")
    String getTenantDomain(@PathVariable("id") long id, @RequestParam Map<String, Object> params);

    @PostMapping("/internal/admin/tenant-domains")
    String createTenantDomain(@RequestBody Map<String, Object> body);

    @PutMapping("/internal/admin/tenant-domains/{id}")
    String updateTenantDomain(@PathVariable("id") long id, @RequestBody Map<String, Object> body);

    @DeleteMapping("/internal/admin/tenant-domains/{id}")
    String deleteTenantDomain(@PathVariable("id") long id, @RequestParam Map<String, Object> params);

    /**
     * 查询网关 GateShield 配置（数据库快照）。
     */
    @GetMapping("/internal/admin/gateway-risk-config/current")
    String getGatewayRiskConfigCurrent();

    /**
     * 更新网关 GateShield 配置（写库并发布变更消息）。
     */
    @PutMapping("/internal/admin/gateway-risk-config")
    String updateGatewayRiskConfig(@RequestBody Map<String, Object> body);

    /**
     * 查询 API Scope 动态规则配置快照（数据库）。
     */
    @GetMapping("/internal/admin/api-scope-rules/current")
    String getApiScopeRulesCurrent();

    /**
     * 更新 API Scope 动态规则配置（全量覆盖）。
     */
    @PutMapping("/internal/admin/api-scope-rules")
    String updateApiScopeRules(@RequestBody BaseApiScopeRuleConfigUpdateRequest body);

    /**
     * 查询公共白名单路径配置快照（数据库）。
     */
    @GetMapping("/internal/admin/security-public-paths/current")
    String getSecurityPublicPathsCurrent();

    /**
     * 更新公共白名单路径配置（全量覆盖）。
     */
    @PutMapping("/internal/admin/security-public-paths")
    String updateSecurityPublicPaths(@RequestBody BaseSecurityPublicPathsConfigUpdateRequest body);
}
