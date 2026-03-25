package com.bootcloud.common.core.trace;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * TraceId 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>TraceId 用于跨服务串联日志与请求链路，方便排查偶现问题。</li>
 *   <li>当前实现关注“可观测性与可落地”，不引入完整的分布式追踪系统。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.trace")
public class TraceProperties {

    /**
     * 是否启用 TraceId。
     */
    private boolean enabled = true;

    /**
     * TraceId HTTP 头名。
     *
     * <p>说明：统一使用 X-Trace-Id。</p>
     */
    private String headerName = "X-Trace-Id";

    /**
     * 是否把 TraceId 回写到响应头。
     */
    private boolean echoResponseHeader = true;

    /**
     * 是否输出启动日志，提示已启用 TraceId。
     */
    private boolean startupLog = true;
}

