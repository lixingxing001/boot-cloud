package com.bootcloud.common.core.trace;

import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;

/**
 * WebClient TraceId 透传 Filter。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>优先从 Reactor Context 读取 traceId，其次从 MDC 读取。</li>
 *   <li>缺失时生成一个新的 traceId，确保调用链可追踪。</li>
 * </ul>
 */
public class TraceIdWebClientCustomizer {

    private final TraceProperties props;

    public TraceIdWebClientCustomizer(TraceProperties props) {
        this.props = props;
    }

    public ExchangeFilterFunction asFilter() {
        if (props == null || !props.isEnabled()) {
            return (req, next) -> next.exchange(req);
        }
        String headerName = StringUtils.hasText(props.getHeaderName()) ? props.getHeaderName().trim() : "X-Trace-Id";
        return (req, next) -> Mono.deferContextual(ctx -> {
            // 说明：
            // 同 introspect 客户端一样，这里也避免直接 String.valueOf(ctx.get(key))，
            // 防止泛型返回值触发 String.valueOf(char[]) 重载推断，出现 String to [C 的 ClassCastException。
            Object traceObj = ctx.hasKey(TraceIdContext.REACTOR_KEY) ? ctx.get(TraceIdContext.REACTOR_KEY) : null;
            String traceIdFromCtx = traceObj == null ? null : String.valueOf(traceObj);
            String resolvedTraceId = resolveTraceId(traceIdFromCtx);
            ClientRequest newReq = ClientRequest.from(req)
                    .headers(h -> {
                        if (!h.containsKey(headerName)) {
                            h.set(headerName, resolvedTraceId);
                        }
                    })
                    .build();
            return next.exchange(newReq);
        });
    }

    private String resolveTraceId(String traceIdFromCtx) {
        String traceId = StringUtils.hasText(traceIdFromCtx) ? traceIdFromCtx : TraceIdContext.get();
        if (StringUtils.hasText(traceId)) {
            return traceId;
        }
        return TraceIdGenerator.generate();
    }
}
