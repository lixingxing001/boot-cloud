package com.bootcloud.common.core.internal;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 内部服务 HMAC 认证工具。
 *
 * <p>说明：</p>
 * <ol>
 *   <li>统一签名口径：只签 method 与 path，不签 query，不签 body。</li>
 *   <li>签名串：serviceName:timestampSeconds:METHOD:/path</li>
 *   <li>签名算法：HMAC-SHA256，输出小写 hex。</li>
 *   <li>Header 命名统一：X-Service-Name / X-Internal-Timestamp / X-Internal-Sign</li>
 * </ol>
 */
public final class InternalHmacAuth {

    private InternalHmacAuth() {
    }

    public static final String HEADER_SERVICE_NAME = "X-Service-Name";
    public static final String HEADER_INTERNAL_TIMESTAMP = "X-Internal-Timestamp";
    public static final String HEADER_INTERNAL_SIGN = "X-Internal-Sign";

    /**
     * 生成秒级时间戳字符串。
     */
    public static String nowTimestampSeconds() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    /**
     * 规范化 path。
     *
     * <p>规则：</p>
     * <ol>
     *   <li>移除 query（问号及其后内容）。</li>
     *   <li>确保以 / 开头。</li>
     *   <li>空值兜底为 /。</li>
     * </ol>
     */
    public static String normalizePath(String maybeUrlOrPath) {
        if (maybeUrlOrPath == null || maybeUrlOrPath.trim().isEmpty()) {
            return "/";
        }
        String s = maybeUrlOrPath.trim();
        int q = s.indexOf('?');
        if (q >= 0) {
            s = s.substring(0, q);
        }
        if (!s.startsWith("/")) {
            s = "/" + s;
        }
        return s.isEmpty() ? "/" : s;
    }

    /**
     * 生成签名。
     */
    public static String sign(String secret, String serviceName, String timestampSeconds, String method, String path) {
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalArgumentException("secret 不能为空");
        }
        if (serviceName == null || serviceName.trim().isEmpty()) {
            throw new IllegalArgumentException("serviceName 不能为空");
        }
        if (timestampSeconds == null || timestampSeconds.trim().isEmpty()) {
            throw new IllegalArgumentException("timestampSeconds 不能为空");
        }
        String m = method == null ? "" : method.trim().toUpperCase();
        String p = normalizePath(path);
        String message = serviceName.trim() + ":" + timestampSeconds.trim() + ":" + m + ":" + p;

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.trim().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] bytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("内部服务签名生成失败", e);
        }
    }

    /**
     * 构建 HMAC 认证头（不包含 traceId）。
     *
     * <p>说明：调用方可以自行额外添加 X-Trace-Id 等 header。</p>
     */
    public static Map<String, String> buildHeaders(String serviceName, String secret, String method, String path) {
        String ts = nowTimestampSeconds();
        String signature = sign(secret, serviceName, ts, method, path);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HEADER_SERVICE_NAME, serviceName);
        headers.put(HEADER_INTERNAL_TIMESTAMP, ts);
        headers.put(HEADER_INTERNAL_SIGN, signature);
        return headers;
    }
}

