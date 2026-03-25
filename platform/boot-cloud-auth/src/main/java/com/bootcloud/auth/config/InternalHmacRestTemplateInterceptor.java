package com.bootcloud.auth.config;

import com.bootcloud.common.core.internal.InternalHmacAuth;
import com.bootcloud.common.core.security.SecurityUserUtils;
import com.bootcloud.common.core.trace.TraceIdContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

/**
 * RestTemplate 内部 HMAC 签名拦截器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一签名口径：只签 method 与 path，不签 query，不签 body。</li>
 *   <li>用于 Go 服务的 /internal 接口调用，避免业务代码手动生成签名与 header。</li>
 *   <li>会兜底透传 X-Trace-Id，便于排障。</li>
 * </ul>
 */
@Slf4j
public class InternalHmacRestTemplateInterceptor implements ClientHttpRequestInterceptor {

    private static final String TRACE_HEADER = "X-Trace-Id";
    private static final String TENANT_HEADER = "X-Tenant-Id";

    private final String serviceName;
    private final String secret;
    private final boolean debugLog;

    public InternalHmacRestTemplateInterceptor(String serviceName, String secret, boolean debugLog) {
        this.serviceName = serviceName;
        this.secret = secret;
        this.debugLog = debugLog;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        if (request == null) {
            return execution.execute(request, body);
        }

        if (!StringUtils.hasText(serviceName) || !StringUtils.hasText(secret)) {
            // 说明：缺配置时不阻断请求，避免启动失败。上游会收到 401 并可通过日志定位。
            if (debugLog) {
                log.warn("内部 RestTemplate 签名拦截器缺少配置：serviceNamePresent={}, secretPresent={}",
                        StringUtils.hasText(serviceName), StringUtils.hasText(secret));
            }
            return execution.execute(request, body);
        }

        URI uri = request.getURI();
        String method = request.getMethod() == null ? "" : request.getMethod().name();
        String path = uri == null ? "/" : InternalHmacAuth.normalizePath(uri.getPath());

        Map<String, String> h = InternalHmacAuth.buildHeaders(serviceName, secret, method, path);
        HttpHeaders headers = request.getHeaders();
        headers.set(InternalHmacAuth.HEADER_SERVICE_NAME, h.get(InternalHmacAuth.HEADER_SERVICE_NAME));
        headers.set(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP, h.get(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP));
        headers.set(InternalHmacAuth.HEADER_INTERNAL_SIGN, h.get(InternalHmacAuth.HEADER_INTERNAL_SIGN));

        String traceId = TraceIdContext.get();
        if (!StringUtils.hasText(traceId)) {
            traceId = TraceIdContext.getOrCreate();
        }
        if (StringUtils.hasText(traceId) && !headers.containsKey(TRACE_HEADER)) {
            headers.set(TRACE_HEADER, traceId.trim());
        }

        SecurityUserUtils.getTenantId().ifPresent(tenantId -> {
            if (!headers.containsKey(TENANT_HEADER)) {
                headers.set(TENANT_HEADER, String.valueOf(tenantId));
            }
        });

        if (debugLog) {
            log.debug("内部 RestTemplate 签名注入：method={}, path={}, serviceName={}, traceId={}, tenantId={}",
                    method, path, serviceName, traceId, headers.getFirst(TENANT_HEADER));
        }

        return execution.execute(request, body);
    }
}

