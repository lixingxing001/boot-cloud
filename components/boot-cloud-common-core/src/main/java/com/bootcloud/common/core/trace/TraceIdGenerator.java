package com.bootcloud.common.core.trace;

import java.util.UUID;

/**
 * TraceId 生成器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>生成 32 位无短横 UUID，便于日志检索与复制。</li>
 * </ul>
 */
public final class TraceIdGenerator {

    private TraceIdGenerator() {
    }

    public static String generate() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}

