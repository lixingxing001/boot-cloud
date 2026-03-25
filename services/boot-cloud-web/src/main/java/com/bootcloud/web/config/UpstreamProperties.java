package com.bootcloud.web.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * boot-cloud-web 调用上游服务（典型：boot-cloud-auth）的统一配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该配置主要用于提升可观测性与稳定性，适配“偶现问题”定位。</li>
 *   <li>默认超时较保守，避免连接卡死导致线程长期占用。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.web.upstream")
public class UpstreamProperties {

    /**
     * 连接超时。
     */
    private Duration connectTimeout = Duration.ofSeconds(3);

    /**
     * 读取超时。
     */
    private Duration readTimeout = Duration.ofSeconds(10);

    /**
     * 是否输出上游调用的调试日志（默认关闭，避免生产噪音）。
     *
     * <p>建议排障时临时开启，然后在问题定位后关闭。</p>
     */
    private boolean debugLog = false;

    /**
     * 上游响应体写入日志的最大字符数（会做脱敏与截断）。
     */
    private int maxBodyCharsForLog = 1024;

    /**
     * 是否把上游响应体片段写入 ApiResponse.error.details（会做脱敏与截断）。
     *
     * <p>说明：开启后，前端能拿到更有用的错误线索，同时也要注意避免泄露敏感信息，因此这里会做脱敏。</p>
     */
    private boolean includeBodyInResponseDetails = true;

    /**
     * 上游响应体写入 ApiResponse.error.details 的最大字符数（会做脱敏与截断）。
     */
    private int maxBodyCharsForResponseDetails = 512;
}

