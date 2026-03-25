package com.bootcloud.common.core.trace;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Servlet 场景 TraceId 注入 Filter。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>优先复用请求头的 X-Trace-Id。</li>
 *   <li>缺失时生成新的 traceId，并回写到响应头。</li>
 *   <li>traceId 写入 MDC，便于日志模板输出。</li>
 * </ul>
 */
public class TraceIdServletFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TraceIdServletFilter.class);

    private final TraceProperties properties;

    public TraceIdServletFilter(TraceProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (properties == null || !properties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String headerName = StringUtils.hasText(properties.getHeaderName()) ? properties.getHeaderName().trim() : "X-Trace-Id";
        String incoming = request.getHeader(headerName);
        boolean hasIncoming = StringUtils.hasText(incoming);
        String traceId = hasIncoming ? incoming.trim() : TraceIdGenerator.generate();

        if (!hasIncoming && log.isDebugEnabled()) {
            log.debug("traceId 已生成并注入：method={}, uri={}, traceId={}", request.getMethod(), request.getRequestURI(), traceId);
        }

        TraceIdContext.set(traceId);
        request.setAttribute(TraceIdContext.MDC_KEY, traceId);
        if (properties.isEchoResponseHeader()) {
            response.setHeader(headerName, traceId);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            TraceIdContext.clear();
        }
    }
}
