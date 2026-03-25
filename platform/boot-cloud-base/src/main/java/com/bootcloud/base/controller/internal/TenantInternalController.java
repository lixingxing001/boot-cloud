package com.bootcloud.base.controller.internal;

import com.bootcloud.base.core.tenant.TenantResolveResult;
import com.bootcloud.base.core.tenant.TenantResolveService;
import jakarta.validation.constraints.NotBlank;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 内部接口：给网关/内部服务调用（不要暴露给公网）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当前约定：网关通过 Host（域名）来解析 tenantId。</li>
 *   <li>后续若需要同时支持 header 固定 tenantId、或从 JWT/Token 中解析租户，也可在这里扩展。</li>
 * </ul>
 */
@Validated
@RestController
@RequestMapping("/internal/tenant")
public class TenantInternalController {

    private final TenantResolveService tenantResolveService;

    public TenantInternalController(TenantResolveService tenantResolveService) {
        this.tenantResolveService = tenantResolveService;
    }

    /**
     * 域名解析 tenantId。
     *
     * 示例：GET /internal/tenant/resolve?domain=localhost
     */
    @GetMapping("/resolve")
    public TenantResolveResult resolve(@RequestParam("domain") @NotBlank String domain) {
        return tenantResolveService.resolveByDomain(domain);
    }
}

