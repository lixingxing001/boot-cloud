package com.bootcloud.common.core.trace;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 为 RestTemplate 统一注入 TraceId 透传能力。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>服务内部相互调用时，自动携带 X-Trace-Id。</li>
 *   <li>默认不输出请求体，避免泄露 password、token 等敏感数据。</li>
 * </ul>
 */
public class TraceIdRestTemplateBeanPostProcessor implements BeanPostProcessor {

    private static final Logger log = LoggerFactory.getLogger(TraceIdRestTemplateBeanPostProcessor.class);

    private final TraceProperties props;

    public TraceIdRestTemplateBeanPostProcessor(TraceProperties props) {
        this.props = props;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (!(bean instanceof RestTemplate rt)) {
            return bean;
        }
        if (props == null || !props.isEnabled()) {
            return bean;
        }

        String headerName = StringUtils.hasText(props.getHeaderName()) ? props.getHeaderName().trim() : "X-Trace-Id";

        ClientHttpRequestInterceptor interceptor = new TraceIdRestTemplateInterceptor(headerName);

        // 避免重复添加
        boolean exists = rt.getInterceptors().stream().anyMatch(i -> i instanceof TraceIdRestTemplateInterceptor);
        if (!exists) {
            rt.getInterceptors().add(interceptor);
            if (props.isStartupLog()) {
                log.info("RestTemplate 已注入 TraceId 透传能力：beanName={}, headerName={}", beanName, headerName);
            }
        }
        return rt;
    }

    /**
     * RestTemplate TraceId 透传拦截器。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>只在请求头缺失时写入，避免覆盖上游传入的 traceId。</li>
     *   <li>默认不打印 request body，避免泄露敏感信息。</li>
     * </ul>
     */
    static final class TraceIdRestTemplateInterceptor implements ClientHttpRequestInterceptor {

        private static final Logger log = LoggerFactory.getLogger(TraceIdRestTemplateInterceptor.class);

        private final String headerName;

        TraceIdRestTemplateInterceptor(String headerName) {
            this.headerName = headerName;
        }

        @Override
        public org.springframework.http.client.ClientHttpResponse intercept(
                org.springframework.http.HttpRequest request,
                byte[] body,
                org.springframework.http.client.ClientHttpRequestExecution execution
        ) throws java.io.IOException {
            String existing = request.getHeaders().getFirst(headerName);
            if (!StringUtils.hasText(existing)) {
                // 说明：
                // 这里做一层“兜底透传”：
                // 1) 优先使用 MDC 中的 traceId（正常情况下由 TraceIdServletFilter 写入）
                // 2) 若 MDC 为空，尝试从当前 HttpServletRequest 的 header 读取（防止某些实例/链路中 Filter 未生效）
                // 3) 仍为空则生成新的 traceId
                String traceId = TraceIdContext.get();
                if (!StringUtils.hasText(traceId)) {
                    traceId = resolveFromCurrentRequestHeader(headerName);
                    if (StringUtils.hasText(traceId)) {
                        TraceIdContext.set(traceId);
                        if (log.isDebugEnabled()) {
                            log.debug("RestTemplate 透传 traceId：来源=requestHeader，headerName={}，traceId={}", headerName, traceId);
                        }
                    }
                }
                if (!StringUtils.hasText(traceId)) {
                    traceId = TraceIdGenerator.generate();
                    TraceIdContext.set(traceId);
                    if (log.isDebugEnabled()) {
                        log.debug("RestTemplate 透传 traceId：来源=generated，headerName={}，traceId={}", headerName, traceId);
                    }
                }
                request.getHeaders().set(headerName, traceId.trim());
            }
            return execution.execute(request, body);
        }

        private String resolveFromCurrentRequestHeader(String headerName) {
            try {
                var attrs = RequestContextHolder.getRequestAttributes();
                if (attrs instanceof ServletRequestAttributes sra && sra.getRequest() != null) {
                    String v = sra.getRequest().getHeader(headerName);
                    return StringUtils.hasText(v) ? v.trim() : null;
                }
            } catch (Exception e) {
                // 说明：这里不抛异常，避免影响业务请求；仅在 debug 级别输出，便于排查上下文缺失原因
                if (log.isDebugEnabled()) {
                    log.debug("RestTemplate 读取当前请求 traceId 失败：headerName={}，msg={}", headerName, e.getMessage());
                }
            }
            return null;
        }
    }
}
