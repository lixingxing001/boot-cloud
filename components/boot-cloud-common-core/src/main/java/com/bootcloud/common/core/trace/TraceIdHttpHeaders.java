package com.bootcloud.common.core.trace;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.lang.reflect.Method;

/**
 * TraceId HTTP Header 工具类。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>目的：把 “如何拿到当前链路的 traceId” 这段逻辑收敛到 core，避免每个 Client 都写一遍。</li>
 *   <li>统一头名：X-Trace-Id。</li>
 *   <li>策略：优先复用 TraceIdContext，其次尝试从当前请求头读取，最后生成新的 traceId。</li>
 * </ul>
 */
public final class TraceIdHttpHeaders {

    private static final Logger log = LoggerFactory.getLogger(TraceIdHttpHeaders.class);

    public static final String DEFAULT_HEADER_NAME = "X-Trace-Id";

    private TraceIdHttpHeaders() {
    }

    /**
     * 确保 headers 中存在 X-Trace-Id，并返回最终使用的 traceId。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>若 headers 已包含 X-Trace-Id，复用它并同步到 TraceIdContext。</li>
     *   <li>若 headers 未包含，则从上下文解析或生成，并写入 headers。</li>
     * </ul>
     */
    public static String ensure(HttpHeaders headers) {
        return ensure(headers, DEFAULT_HEADER_NAME);
    }

    public static String ensure(HttpHeaders headers, String headerName) {
        String hn = StringUtils.hasText(headerName) ? headerName.trim() : DEFAULT_HEADER_NAME;

        if (headers != null) {
            String existing = headers.getFirst(hn);
            if (StringUtils.hasText(existing)) {
                String v = existing.trim();
                TraceIdContext.set(v);
                return v;
            }
        }

        String traceId = resolveOrCreate(hn);
        if (headers != null) {
            headers.set(hn, traceId);
        }
        return traceId;
    }

    /**
     * 解析或生成 traceId，并写入 TraceIdContext。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于业务层显式兜底透传，避免偶发拦截器失效导致 traceId 断链。</li>
     * </ul>
     */
    public static String resolveOrCreate() {
        return resolveOrCreate(DEFAULT_HEADER_NAME);
    }

    public static String resolveOrCreate(String headerName) {
        String hn = StringUtils.hasText(headerName) ? headerName.trim() : DEFAULT_HEADER_NAME;

        String fromCtx = TraceIdContext.get();
        if (StringUtils.hasText(fromCtx)) {
            return fromCtx.trim();
        }

        String fromReq = resolveFromCurrentRequestHeader(hn);
        if (StringUtils.hasText(fromReq)) {
            String v = fromReq.trim();
            TraceIdContext.set(v);
            return v;
        }

        String generated = TraceIdGenerator.generate();
        TraceIdContext.set(generated);
        if (log.isDebugEnabled()) {
            log.debug("未获取到上游 traceId，已生成新的 traceId: traceId={}", generated);
        }
        return generated;
    }

    /**
     * 从当前请求头读取 traceId。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>这里使用反射读取 request.getHeader，避免引入 servlet 相关类型，防止 WebFlux 网关启动时报 NoClassDefFoundError。</li>
     * </ul>
     */
    private static String resolveFromCurrentRequestHeader(String headerName) {
        try {
            RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return null;
            }
            Method getRequest = attrs.getClass().getMethod("getRequest");
            Object request = getRequest.invoke(attrs);
            if (request == null) {
                return null;
            }
            Method getHeader = request.getClass().getMethod("getHeader", String.class);
            Object v = getHeader.invoke(request, headerName);
            if (v instanceof String s && StringUtils.hasText(s)) {
                return s.trim();
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("读取当前请求 traceId 失败: msg={}", e.getMessage());
            }
        }
        return null;
    }
}

