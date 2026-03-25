package com.bootcloud.common.core.trace;

import org.slf4j.MDC;
import org.springframework.util.StringUtils;

/**
 * TraceId 上下文。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>Servlet 场景使用 MDC 存储 traceId，便于日志模板输出。</li>
 *   <li>WebFlux 场景主要依赖请求头透传与 Gateway 全局 Filter；日志 MDC 由具体项目决定是否启用上下文传播。</li>
 * </ul>
 */
public final class TraceIdContext {

    private TraceIdContext() {
    }

    /**
     * MDC 中的 key。
     *
     * <p>说明：建议日志模板输出 %X{traceId}。</p>
     */
    public static final String MDC_KEY = "traceId";

    /**
     * Reactor Context key（给 WebFlux 使用）。
     */
    public static final String REACTOR_KEY = "boot.cloud.traceId";

    public static String get() {
        return MDC.get(MDC_KEY);
    }

    public static String getOrCreate() {
        String v = get();
        if (StringUtils.hasText(v)) {
            return v.trim();
        }
        String id = TraceIdGenerator.generate();
        set(id);
        return id;
    }

    public static void set(String traceId) {
        if (!StringUtils.hasText(traceId)) {
            return;
        }
        MDC.put(MDC_KEY, traceId.trim());
    }

    public static void clear() {
        MDC.remove(MDC_KEY);
    }
}

