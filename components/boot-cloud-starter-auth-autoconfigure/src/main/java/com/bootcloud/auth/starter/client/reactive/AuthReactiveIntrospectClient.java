package com.bootcloud.auth.starter.client.reactive;

import com.bootcloud.auth.starter.core.AuthClientConfig;
import com.bootcloud.auth.starter.dto.IntrospectResponse;
import com.bootcloud.auth.starter.util.BasicAuthUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * WebFlux 场景下调用 boot-cloud-auth 的 token 自省封装（WebClient）。
 */
public class AuthReactiveIntrospectClient {

    private static final Logger log = LoggerFactory.getLogger(AuthReactiveIntrospectClient.class);
    /**
     * Reactor Context 中存放 traceId 的 key。
     */
    private static final String TRACE_REACTOR_KEY = "boot.cloud.traceId";

    private final WebClient webClient;
    private final AuthClientConfig config;

    public AuthReactiveIntrospectClient(WebClient webClient, AuthClientConfig config) {
        this.webClient = webClient;
        this.config = config;
    }

    /**
     * token 自省并返回“调用状态 + 自省结果”。
     *
     * <ul>
     *   <li>当认证中心暂时不可用时，调用状态为上游不可用。</li>
     *   <li>当认证中心正常返回 200 且 token inactive 时，调用状态为成功，业务方可按“token 无效”处理。</li>
     *   <li>这样可以避免把“上游故障”误判成“用户 token 失效”。</li>
     * </ul>
     */
    public Mono<IntrospectCallResult> introspectWithStatus(String tenantId, String token) {
        return Mono.deferContextual(ctx -> {
            Object traceObj = ctx.hasKey(TRACE_REACTOR_KEY) ? ctx.get(TRACE_REACTOR_KEY) : null;
            String traceId = traceObj == null ? "" : String.valueOf(traceObj);
            if (log.isDebugEnabled() && traceObj != null && !(traceObj instanceof String)) {
                log.debug("introspect traceId 类型异常：tenantId={}，traceIdClass={}", tenantId, traceObj.getClass().getName());
            }

            if (!StringUtils.hasText(token)) {
                if (log.isDebugEnabled()) {
                    log.debug("introspect skipped: empty token, tenantId={}, traceId={}", tenantId, traceId);
                }
                return Mono.just(IntrospectCallResult.success(inactive()));
            }

            // 当 useBasicAuth=false 且缺少 client_id 时，属于本地配置错误。
            // 这里返回上游不可用语义，交给调用方按“服务暂不可用”处理。
            if (!config.isUseBasicAuth() && !StringUtils.hasText(config.getClientId())) {
                String msg = "introspect config missing clientId";
                log.warn("{}: tenantId={}, traceId={}", msg, tenantId, traceId);
                return Mono.just(IntrospectCallResult.upstreamUnavailable(null, msg));
            }

            String body = buildFormBody(b -> {
                b.add("token", token);
                if (!config.isUseBasicAuth()) {
                    b.add("client_id", config.getClientId());
                    if (StringUtils.hasText(config.getClientSecret())) {
                        b.add("client_secret", config.getClientSecret());
                    }
                }
            });

            if (log.isDebugEnabled()) {
                log.debug("introspect request: url={}, tenantId={}, useBasicAuth={}, traceId={}",
                        config.introspectUrl(), tenantId, config.isUseBasicAuth(), traceId);
                log.debug("introspect request body built: keys={}, bodyLen={}, tenantId={}, traceId={}",
                        config.isUseBasicAuth() ? "[token]" : "[token,client_id,client_secret]",
                        body.length(),
                        tenantId,
                        traceId);
            }

            return webClient.post()
                    .uri(URI.create(config.introspectUrl()))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .header(config.getTenantHeaderName(), tenantId)
                    .headers(h -> {
                        if (StringUtils.hasText(traceId)) {
                            h.set("X-Trace-Id", traceId);
                        }
                        if (config.isUseBasicAuth()) {
                            if (!StringUtils.hasText(config.getClientId())) {
                                return;
                            }
                            h.set("Authorization", BasicAuthUtil.basic(config.getClientId(), config.getClientSecret()));
                        }
                    })
                    .bodyValue(body)
                    .exchangeToMono(resp -> {
                        if (resp.statusCode().is2xxSuccessful()) {
                            return resp.bodyToMono(IntrospectResponse.class)
                                    .map(IntrospectCallResult::success)
                                    .switchIfEmpty(Mono.just(IntrospectCallResult.success(inactive())));
                        }
                        return resp.bodyToMono(String.class)
                                .defaultIfEmpty("")
                                .flatMap(respBody -> {
                                    String oauthError = extractOAuthField(respBody, "error");
                                    String oauthDescription = extractOAuthField(respBody, "error_description");
                                    if (log.isDebugEnabled()) {
                                        String snippet = respBody.length() > 256 ? respBody.substring(0, 256) : respBody;
                                        log.debug("introspect non-2xx: status={}, tenantId={}, traceId={}, oauthError={}, oauthDescription={}, bodySnippet={}",
                                                resp.statusCode().value(), tenantId, traceId, oauthError, oauthDescription, snippet);
                                    }
                                    if (resp.statusCode().is4xxClientError()) {
                                        return Mono.just(IntrospectCallResult.businessRejected(
                                                resp.statusCode().value(),
                                                oauthError,
                                                oauthDescription
                                        ));
                                    }
                                    return Mono.just(IntrospectCallResult.upstreamUnavailable(resp.statusCode().value(), "introspect status not 2xx"));
                                });
                    })
                    .onErrorResume(e -> {
                        if (log.isDebugEnabled()) {
                            log.debug("introspect failed: tenantId={}, traceId={}, msg={}", tenantId, traceId, e.getMessage());
                        }
                        return Mono.just(IntrospectCallResult.upstreamUnavailable(null, e.getMessage()));
                    });
        });
    }

    public Mono<IntrospectResponse> introspect(String tenantId, String token) {
        // 保持历史接口语义：调用失败统一返回 inactive。
        return introspectWithStatus(tenantId, token)
                .map(IntrospectCallResult::response);
    }

    private static IntrospectResponse inactive() {
        IntrospectResponse r = new IntrospectResponse();
        r.setActive(false);
        return r;
    }

    /**
     * 从 OAuth2 标准错误体中提取字段。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>这里保持轻量解析，只取 error/error_description，避免引入额外 DTO。</li>
     *   <li>非 JSON 或字段缺失时返回空串，由调用方继续按兜底逻辑处理。</li>
     * </ul>
     */
    private static String extractOAuthField(String rawBody, String fieldName) {
        if (!StringUtils.hasText(rawBody) || !StringUtils.hasText(fieldName)) {
            return "";
        }
        String body = rawBody.trim();
        if (!body.startsWith("{") || !body.endsWith("}")) {
            return "";
        }
        String quotedField = "\"" + fieldName.trim() + "\"";
        int keyIdx = body.indexOf(quotedField);
        if (keyIdx < 0) {
            return "";
        }
        int colonIdx = body.indexOf(':', keyIdx + quotedField.length());
        if (colonIdx < 0) {
            return "";
        }
        int startQuote = body.indexOf('"', colonIdx + 1);
        if (startQuote < 0) {
            return "";
        }
        int endQuote = startQuote + 1;
        boolean escaped = false;
        while (endQuote < body.length()) {
            char current = body.charAt(endQuote);
            if (current == '"' && !escaped) {
                break;
            }
            escaped = current == '\\' && !escaped;
            if (current != '\\') {
                escaped = false;
            }
            endQuote++;
        }
        if (endQuote >= body.length()) {
            return "";
        }
        return body.substring(startQuote + 1, endQuote).trim();
    }

    private static String buildFormBody(java.util.function.Consumer<FormBodyBuilder> consumer) {
        FormBodyBuilder b = new FormBodyBuilder();
        consumer.accept(b);
        return b.build();
    }

    static final class FormBodyBuilder {
        private final StringBuilder sb = new StringBuilder();

        void add(String key, String value) {
            if (!StringUtils.hasText(key) || value == null) {
                return;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            sb.append('=');
            sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        }

        String build() {
            return sb.toString();
        }
    }

    /**
     * 自省调用结果。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>response：自省返回体（上游失败时默认为 inactive）。</li>
     *   <li>upstreamAvailable：是否成功访问并拿到可用自省结果。</li>
     *   <li>upstreamStatus：上游 HTTP 状态码，连接失败时为空。</li>
     *   <li>message：调试信息（不含敏感 token）。</li>
     * </ul>
     */
    public static final class IntrospectCallResult {
        private final IntrospectResponse response;
        private final boolean upstreamAvailable;
        private final Integer upstreamStatus;
        private final String message;
        private final String oauthError;
        private final String oauthDescription;
        private final ResultType resultType;

        private IntrospectCallResult(
                IntrospectResponse response,
                boolean upstreamAvailable,
                Integer upstreamStatus,
                String message,
                String oauthError,
                String oauthDescription,
                ResultType resultType
        ) {
            this.response = response == null ? inactive() : response;
            this.upstreamAvailable = upstreamAvailable;
            this.upstreamStatus = upstreamStatus;
            this.message = message;
            this.oauthError = oauthError == null ? "" : oauthError.trim();
            this.oauthDescription = oauthDescription == null ? "" : oauthDescription.trim();
            this.resultType = resultType == null ? ResultType.UPSTREAM_UNAVAILABLE : resultType;
        }

        public static IntrospectCallResult success(IntrospectResponse response) {
            return new IntrospectCallResult(response, true, 200, "ok", "", "", ResultType.SUCCESS);
        }

        public static IntrospectCallResult businessRejected(Integer upstreamStatus, String oauthError, String oauthDescription) {
            String error = oauthError == null ? "" : oauthError.trim();
            String description = oauthDescription == null ? "" : oauthDescription.trim();
            String message = StringUtils.hasText(description) ? description : error;
            return new IntrospectCallResult(inactive(), true, upstreamStatus, message, error, description, ResultType.BUSINESS_REJECTED);
        }

        public static IntrospectCallResult upstreamUnavailable(Integer upstreamStatus, String message) {
            return new IntrospectCallResult(inactive(), false, upstreamStatus, message, "", "", ResultType.UPSTREAM_UNAVAILABLE);
        }

        public IntrospectResponse response() {
            return response;
        }

        public boolean upstreamAvailable() {
            return upstreamAvailable;
        }

        public Integer upstreamStatus() {
            return upstreamStatus;
        }

        public String message() {
            return message;
        }

        public String oauthError() {
            return oauthError;
        }

        public String oauthDescription() {
            return oauthDescription;
        }

        public boolean businessRejected() {
            return resultType == ResultType.BUSINESS_REJECTED;
        }

        public ResultType resultType() {
            return resultType;
        }
    }

    /**
     * 自省调用结果类型。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>SUCCESS：上游 2xx，拿到了标准自省结果。</li>
     *   <li>BUSINESS_REJECTED：上游 4xx 且返回了明确 OAuth 错误，说明认证中心正常可用，但拒绝当前请求。</li>
     *   <li>UPSTREAM_UNAVAILABLE：网络失败、5xx、空响应等真正的上游不可用。</li>
     * </ul>
     */
    public enum ResultType {
        SUCCESS,
        BUSINESS_REJECTED,
        UPSTREAM_UNAVAILABLE
    }
}
