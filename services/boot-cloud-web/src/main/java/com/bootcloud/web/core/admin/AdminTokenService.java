package com.bootcloud.web.core.admin;

import com.bootcloud.auth.starter.config.AuthClientProperties;
import com.bootcloud.common.core.error.AppException;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.common.core.trace.TraceIdContext;
import com.bootcloud.common.feign.api.AuthOAuthApi;
import com.bootcloud.web.config.AdminAuthProperties;
import com.bootcloud.web.config.UpstreamProperties;
import com.bootcloud.web.core.util.LogSafeUtil;
import feign.FeignException;
import feign.RetryableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 后台管理员登录 token 服务（boot-cloud-web -> boot-cloud-auth）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该服务对应“过渡方案A”：后台页面仍调用后台资源服务，但登录 token 由统一认证中心 boot-cloud-auth 签发。</li>
 *   <li>token 最终用于网关路径：/api/admin/**（后台资源服务作为 OAuth2 资源服务自省校验）。</li>
 * </ul>
 */
@Slf4j
@Service
public class AdminTokenService {

    private final AuthOAuthApi authApi;
    private final AuthClientProperties evmAuthClientProperties;
    private final AdminAuthProperties adminAuthProperties;
    private final UpstreamProperties upstreamProperties;

    public AdminTokenService(
            AuthOAuthApi authApi,
            AuthClientProperties evmAuthClientProperties,
            AdminAuthProperties adminAuthProperties,
            UpstreamProperties upstreamProperties
    ) {
        this.authApi = authApi;
        this.evmAuthClientProperties = evmAuthClientProperties;
        this.adminAuthProperties = adminAuthProperties;
        this.upstreamProperties = upstreamProperties;
    }

    public ResponseEntity<String> passwordToken(String tenantId, String username, String password, String deviceId) {
        if (!StringUtils.hasText(tenantId)) {
            log.error("后台管理员换 token 失败：缺少 X-Tenant-Id，拒绝继续回退到固定租户");
            throw badRequest("缺少租户信息，请先同步后台运行时默认租户");
        }
        if (!StringUtils.hasText(username)) {
            throw badRequest("username 不能为空");
        }
        if (!StringUtils.hasText(password)) {
            throw badRequest("password 不能为空");
        }
        if (!StringUtils.hasText(deviceId)) {
            // 说明：deviceId 用于后台多会话隔离，缺失时仍可登录，但会退化为“同账号互相挤掉”。
            log.warn("后台管理员换 token：deviceId 为空，可能导致同账号多端互相挤掉，tenantId={}, username={}", tenantId, username.trim());
        }

        String baseUrl = evmAuthClientProperties.getBaseUrl();
        String tokenPath = evmAuthClientProperties.getTokenPath();
        String url = (StringUtils.hasText(baseUrl) ? baseUrl : "http://boot-cloud-auth")
                + (StringUtils.hasText(tokenPath) ? tokenPath : "/oauth/token");

        String clientId = adminAuthProperties.getClientId();
        String clientSecret = adminAuthProperties.getClientSecret();
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            log.warn("后台管理员换 token 失败：未配置 boot.cloud.web.admin-auth.client-id/client-secret");
            throw serverError("后台 OAuth2 client 未配置（建议检查 boot.cloud.web.admin-auth.*）");
        }

        String traceId = TraceIdContext.get();
        log.info("后台管理员换 token：tenantId={}, clientId={}, username={}, deviceId={}, traceId={}", tenantId, clientId, username.trim(), maskDeviceId(deviceId), traceId);

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        String tenantHeaderName = StringUtils.hasText(evmAuthClientProperties.getTenantHeaderName())
                ? evmAuthClientProperties.getTenantHeaderName().trim()
                : "X-Tenant-Id";
        headers.put(tenantHeaderName, tenantId);

        // 说明：
        // 这里显式透传 X-Trace-Id，作为双保险。
        // 背景：理论上 boot-cloud-common-core 会给 RestTemplate 注入拦截器自动透传 traceId，
        // 但在某些实例上可能因为 Bean 初始化顺序导致拦截器未生效，从而出现“boot-cloud-auth 生成新 traceId”的问题。
        // 显式写入可确保 boot-cloud-web -> boot-cloud-auth 的关键链路（登录换 token）traceId 一致。
        if (StringUtils.hasText(traceId)) {
            headers.put("X-Trace-Id", traceId.trim());
        } else {
            String created = TraceIdContext.getOrCreate();
            headers.put("X-Trace-Id", created);
            traceId = created;
        }

        // 兼容两种方式：Basic 或 form（默认 Basic）
        if (adminAuthProperties.isUseBasicAuth()) {
            String basic = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            headers.put(HttpHeaders.AUTHORIZATION, "Basic " + basic);
        }

        // 说明：
        // 这里改为“手工拼表单字符串”，规避 MultiValueMap 在部分环境下未按表单写入 body 的问题。
        // 关键点：只对 value 做 URL 编码，不打印 value，避免泄露 password/client_secret。
        String body = buildFormBody(b -> {
            b.add("grant_type", "admin_password");
            b.add("client_id", clientId);
            if (!adminAuthProperties.isUseBasicAuth()) {
                b.add("client_secret", clientSecret);
            }
            b.add("username", username.trim());
            b.add("password", password);
            if (StringUtils.hasText(deviceId)) {
                b.add("device_id", deviceId.trim());
            }
        });

        log.debug("后台管理员换 token 请求参数已构造：keys={}, bodyLen={}, traceId={}",
                adminAuthProperties.isUseBasicAuth()
                        ? "[grant_type,client_id,username,password,device_id]"
                        : "[grant_type,client_id,client_secret,username,password,device_id]",
                body.length(),
                traceId);

        long startNs = System.nanoTime();
        try {
            String resp = authApi.tokenRaw(headers, body);
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            log.info("后台管理员换 token 调用完成：status=200, costMs={}, traceId={}", costMs, traceId);
            return ResponseEntity.ok(resp);
        } catch (RetryableException e) {
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            log.warn("后台管理员换 token 上游连接异常：url={}, costMs={}, traceId={}, msg={}", url, costMs, traceId, e.getMessage());
            throw upstreamConnectFailed("上游连接失败", traceId, url, e);
        } catch (FeignException e) {
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            String bodySnippet = LogSafeUtil.sanitizeAndTruncate(e.contentUTF8(),
                    upstreamProperties != null ? upstreamProperties.getMaxBodyCharsForLog() : 1024);
            log.warn("后台管理员换 token 上游返回异常：url={}, status={}, costMs={}, traceId={}, bodySnippet={}",
                    url, e.status(), costMs, traceId, bodySnippet);
            throw e;
        }
    }

    /**
     * 后台管理员刷新 token（refresh_token -> token）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>refresh_token 与签发它的 client 绑定，因此后台也需要独立的 refresh 接口（仍由 BFF 代持 secret）。</li>
     * </ul>
     */
    public ResponseEntity<String> refreshToken(String tenantId, String refreshToken) {
        return refreshToken(tenantId, refreshToken, null);
    }

    public ResponseEntity<String> refreshToken(String tenantId, String refreshToken, String deviceId) {
        if (!StringUtils.hasText(tenantId)) {
            log.error("后台刷新 token 失败：缺少 X-Tenant-Id，拒绝继续回退到固定租户");
            throw badRequest("缺少租户信息，请先同步后台运行时默认租户");
        }
        if (!StringUtils.hasText(refreshToken)) {
            throw badRequest("refreshToken 不能为空");
        }
        if (!StringUtils.hasText(deviceId)) {
            log.warn("后台刷新 token：deviceId 为空，可能导致同账号多端互相挤掉，tenantId={}", tenantId);
        }

        String baseUrl = evmAuthClientProperties.getBaseUrl();
        String tokenPath = evmAuthClientProperties.getTokenPath();
        String url = (StringUtils.hasText(baseUrl) ? baseUrl : "http://boot-cloud-auth")
                + (StringUtils.hasText(tokenPath) ? tokenPath : "/oauth/token");

        String clientId = adminAuthProperties.getClientId();
        String clientSecret = adminAuthProperties.getClientSecret();
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            log.warn("后台刷新 token 失败：未配置 boot.cloud.web.admin-auth.client-id/client-secret");
            throw serverError("后台 OAuth2 client 未配置（boot.cloud.web.admin-auth.*）");
        }

        log.debug("后台刷新 token：tenantId={}, clientId={}, deviceId={}", tenantId, clientId, maskDeviceId(deviceId));

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        String tenantHeaderName = StringUtils.hasText(evmAuthClientProperties.getTenantHeaderName())
                ? evmAuthClientProperties.getTenantHeaderName().trim()
                : "X-Tenant-Id";
        headers.put(tenantHeaderName, tenantId);

        // 说明：刷新 token 同样透传 X-Trace-Id，便于排查偶现 refresh 失败。
        String traceId = TraceIdContext.get();
        if (!StringUtils.hasText(traceId)) {
            traceId = TraceIdContext.getOrCreate();
        }
        headers.put("X-Trace-Id", traceId.trim());
        if (adminAuthProperties.isUseBasicAuth()) {
            String basic = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            headers.put(HttpHeaders.AUTHORIZATION, "Basic " + basic);
        }

        String body = buildFormBody(b -> {
            b.add("grant_type", "refresh_token");
            b.add("client_id", clientId);
            if (!adminAuthProperties.isUseBasicAuth()) {
                b.add("client_secret", clientSecret);
            }
            b.add("refresh_token", refreshToken.trim());
            if (StringUtils.hasText(deviceId)) {
                b.add("device_id", deviceId.trim());
            }
        });

        log.debug("后台刷新 token 请求参数已构造：keys={}, bodyLen={}, traceId={}",
                adminAuthProperties.isUseBasicAuth()
                        ? "[grant_type,client_id,refresh_token,device_id]"
                        : "[grant_type,client_id,client_secret,refresh_token,device_id]",
                body.length(),
                traceId);

        long startNs = System.nanoTime();
        try {
            String resp = authApi.tokenRaw(headers, body);
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            log.debug("后台刷新 token 调用完成：status=200, costMs={}, traceId={}", costMs, traceId);
            return ResponseEntity.ok(resp);
        } catch (RetryableException e) {
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            log.warn("后台刷新 token 上游连接异常：url={}, costMs={}, traceId={}, msg={}", url, costMs, traceId, e.getMessage());
            throw upstreamConnectFailed("上游连接失败", traceId, url, e);
        } catch (FeignException e) {
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            String bodySnippet = LogSafeUtil.sanitizeAndTruncate(e.contentUTF8(),
                    upstreamProperties != null ? upstreamProperties.getMaxBodyCharsForLog() : 1024);
            log.warn("后台刷新 token 上游返回异常：url={}, status={}, costMs={}, traceId={}, bodySnippet={}",
                    url, e.status(), costMs, traceId, bodySnippet);
            throw e;
        }
    }

    /**
     * 后台管理员登出：撤销 token（/oauth/revoke）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于“服务端真实登出”。</li>
     *   <li>建议同时撤销 access_token 与 refresh_token。</li>
     *   <li>为实现“只登出当前设备”，需要透传 device_id。</li>
     * </ul>
     */
    public ResponseEntity<String> revokeToken(String tenantId, String token, String tokenTypeHint, String deviceId) {
        if (!StringUtils.hasText(tenantId)) {
            log.error("后台撤销 token 失败：缺少 X-Tenant-Id，拒绝继续回退到固定租户");
            throw badRequest("缺少租户信息，请先同步后台运行时默认租户");
        }
        if (!StringUtils.hasText(token)) {
            throw badRequest("token 不能为空");
        }

        String baseUrl = evmAuthClientProperties.getBaseUrl();
        String revokePath = evmAuthClientProperties.getRevokePath();
        String url = (StringUtils.hasText(baseUrl) ? baseUrl : "http://boot-cloud-auth")
                + (StringUtils.hasText(revokePath) ? revokePath : "/oauth/revoke");

        String clientId = adminAuthProperties.getClientId();
        String clientSecret = adminAuthProperties.getClientSecret();
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            log.warn("后台撤销 token 失败：未配置 boot.cloud.web.admin-auth.client-id/client-secret");
            throw serverError("后台 OAuth2 client 未配置（boot.cloud.web.admin-auth.*）");
        }

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        String tenantHeaderName = StringUtils.hasText(evmAuthClientProperties.getTenantHeaderName())
                ? evmAuthClientProperties.getTenantHeaderName().trim()
                : "X-Tenant-Id";
        headers.put(tenantHeaderName, tenantId);

        String traceId = TraceIdContext.getOrCreate();
        headers.put("X-Trace-Id", traceId.trim());
        if (adminAuthProperties.isUseBasicAuth()) {
            String basic = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            headers.put(HttpHeaders.AUTHORIZATION, "Basic " + basic);
        }

        String hint = StringUtils.hasText(tokenTypeHint) ? tokenTypeHint.trim() : "";
        String body = buildFormBody(b -> {
            b.add("client_id", clientId);
            if (!adminAuthProperties.isUseBasicAuth()) {
                b.add("client_secret", clientSecret);
            }
            b.add("token", token.trim());
            if (StringUtils.hasText(hint)) {
                b.add("token_type_hint", hint);
            }
            if (StringUtils.hasText(deviceId)) {
                b.add("device_id", deviceId.trim());
            }
        });

        if (log.isDebugEnabled()) {
            log.debug("后台撤销 token：tenantId={}, tokenTypeHint={}, tokenLen={}, deviceId={}, bodyLen={}, traceId={}",
                    tenantId,
                    hint,
                    token.length(),
                    maskDeviceId(deviceId),
                    body.length(),
                    traceId);
        }

        long startNs = System.nanoTime();
        try {
            String resp = authApi.revokeRaw(headers, body);
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            log.debug("后台撤销 token 调用完成：status=200, costMs={}, traceId={}", costMs, traceId);
            return ResponseEntity.ok(resp);
        } catch (RetryableException e) {
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            log.warn("后台撤销 token 上游连接异常：url={}, costMs={}, traceId={}, msg={}", url, costMs, traceId, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body("{\"error\":\"upstream_unavailable\",\"traceId\":\"" + traceId + "\"}");
        } catch (FeignException e) {
            long costMs = (System.nanoTime() - startNs) / 1_000_000;
            String bodySnippet = LogSafeUtil.sanitizeAndTruncate(e.contentUTF8(),
                    upstreamProperties != null ? upstreamProperties.getMaxBodyCharsForLog() : 1024);
            log.warn("后台撤销 token 上游返回异常：url={}, status={}, costMs={}, traceId={}, bodySnippet={}",
                    url, e.status(), costMs, traceId, bodySnippet);
            // 说明：登出接口需要尽量幂等，这里把上游 body 原样返回，便于前端与日志排查
            return ResponseEntity.ok(e.contentUTF8());
        }
    }

    private String maskDeviceId(String deviceId) {
        if (!StringUtils.hasText(deviceId)) {
            return "";
        }
        String v = deviceId.trim();
        if (v.length() <= 8) {
            return v;
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    /**
     * 轻量表单拼接器。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>只负责拼接与 URL 编码，不负责校验业务合法性。</li>
     *   <li>编码方式使用 UTF-8，符合 application/x-www-form-urlencoded 约定。</li>
     * </ul>
     */
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
     * 统一构造 400 业务异常，便于全局异常层输出统一错误码。
     */
    private static AppException badRequest(String message) {
        return new AppException(CommonErrorCode.BAD_REQUEST, message);
    }

    /**
     * 统一构造 500 业务异常，用于配置缺失等服务端问题。
     */
    private static AppException serverError(String message) {
        return new AppException(CommonErrorCode.SERVER_ERROR, message);
    }

    /**
     * 构造上游连接失败异常，并附带必要调试字段。
     */
    private static AppException upstreamConnectFailed(String message, String traceId, String upstreamUrl, Throwable cause) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("traceId", traceId);
        details.put("upstreamUrl", upstreamUrl);
        return new AppException(CommonErrorCode.UPSTREAM_CONNECT_FAILED, message, null, details, cause);
    }
}
