package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 网关 GateShield 配置 DB 同步参数。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>目标：由 boot-cloud-base 承载 GateShield 配置，网关通过 MQ 事件触发拉取。</li>
 *   <li>兜底：保留低频定时拉取，处理消息丢失或消费者重启场景。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.gateway.risk.db-sync")
public class GatewayRiskSyncProperties {

    /**
     * 总开关。
     */
    private boolean enabled = false;

    /**
     * 数据来源模式。
     */
    private SourceMode sourceMode = SourceMode.HYBRID;

    /**
     * 配置中心服务名（Nacos serviceId）。
     */
    private String baseServiceId = "boot-cloud-base";

    /**
     * boot-cloud-base 查询当前配置的接口路径。
     */
    private String fetchPath = "/internal/admin/gateway-risk-config/current";

    /**
     * 拉取超时时间（毫秒）。
     */
    private long fetchTimeoutMs = 3000L;

    /**
     * MQ 触发开关。
     */
    private boolean mqEnabled = true;

    /**
     * 低频兜底拉取开关。
     */
    private boolean fallbackPullEnabled = true;

    /**
     * 低频兜底拉取周期（毫秒）。
     */
    private long fallbackPullIntervalMs = 600000L;

    /**
     * 首次低频兜底拉取延时（毫秒）。
     */
    private long fallbackPullInitialDelayMs = 120000L;

    public enum SourceMode {
        /**
         * 仅使用 Nacos 配置，不启用 DB 同步。
         */
        NACOS_ONLY,
        /**
         * 优先 DB，同步失败时保留当前内存配置（通常来自 Nacos）。
         */
        HYBRID,
        /**
         * 仅使用 DB，拉取失败会记录错误日志并保持上一次已加载配置。
         */
        DB_ONLY
    }
}
