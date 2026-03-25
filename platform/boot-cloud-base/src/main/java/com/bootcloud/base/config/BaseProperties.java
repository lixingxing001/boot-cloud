package com.bootcloud.base.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * boot-cloud-base 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>脚手架保留默认租户兜底能力，便于开发环境快速启动。</li>
 *   <li>网关可逐步切换到按域名解析 tenantId 的模式。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.base")
public class BaseProperties {

    /**
     * 当域名未配置映射时返回的默认租户 ID。
     *
     * <p>默认值建议保持 1，便于开发环境快速启动。</p>
     */
    private long defaultTenantId = 1L;

    /**
     * 当域名未找到映射时，是否返回错误（true）还是返回默认 tenantId（false）。
     *
     * <p>开发环境可先设为 false；生产环境建议根据租户治理策略切换为 true。</p>
     */
    private boolean failOnNotFound = false;
}
