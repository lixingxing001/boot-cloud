package com.bootcloud.common.core.error;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 错误详情归一化工具。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一输出严格结构：traceId/reasonCode/reasonMessage/upstream/context。</li>
 *   <li>不再透传旧平铺字段，避免前端继续走历史分支。</li>
 * </ul>
 */
public final class ErrorDetailsNormalizer {

    private static final Logger log = LoggerFactory.getLogger(ErrorDetailsNormalizer.class);

    private static final Set<String> ROOT_RESERVED_KEYS = Set.of(
            "traceId", "trace_id",
            "reasonCode", "reason_code",
            "reasonMessage", "reason_message",
            "rejectCode", "reject_code",
            "rejectReason", "reject_reason",
            "upstreamCode", "upstream_code",
            "upstreamMessage", "upstream_message",
            "upstreamDescription", "upstream_description",
            "upstreamService", "upstream_service",
            "upstreamStatus", "upstream_status",
            "upstreamBodySnippet", "upstream_body_snippet",
            "oauthErrorCode", "oauthErrorDescription", "oauthErrorDesc",
            "oauth_code", "oauth_description",
            "error_code",
            "legacyCode",
            "upstream", "context");

    private static final Set<String> UPSTREAM_RESERVED_KEYS = Set.of(
            "service", "upstreamService", "upstream_service",
            "status", "upstreamStatus", "upstream_status",
            "code", "upstreamCode", "upstream_code", "oauthErrorCode", "oauth_code", "error_code",
            "message", "upstreamMessage", "upstream_message",
            "upstreamDescription", "upstream_description",
            "oauthErrorDescription", "oauthErrorDesc", "oauth_description",
            "bodySnippet", "upstreamBodySnippet", "upstream_body_snippet");

    private ErrorDetailsNormalizer() {
    }

    /**
     * 归一化 details。
     *
     * <p>严格返回固定结构，避免旧字段继续外溢。</p>
     */
    public static Object normalize(Object details) {
        Map<String, Object> source = asStringKeyMap(details);
        if (!(details instanceof Map<?, ?>) && details != null) {
            // 调试信息保留在 context，避免原始 details 丢失。
            source.put("rawDetails", details);
        }

        String traceId = firstText(source, "traceId", "trace_id");
        Map<String, Object> upstream = normalizeUpstream(source, asStringKeyMap(source.get("upstream")));
        Map<String, Object> context = normalizeContext(source, asStringKeyMap(source.get("context")));

        String reasonCode = firstText(source,
                "reasonCode",
                "reason_code",
                "rejectCode",
                "reject_code",
                "upstreamCode",
                "upstream_code",
                "oauthErrorCode");
        if (!hasText(reasonCode)) {
            reasonCode = firstText(source, "oauth_code", "error_code");
        }
        if (!hasText(reasonCode)) {
            reasonCode = firstText(upstream, "code");
        }

        String reasonMessage = firstText(source,
                "reasonMessage",
                "reason_message",
                "rejectReason",
                "reject_reason",
                "upstreamMessage",
                "upstream_message",
                "upstreamDescription",
                "upstream_description",
                "oauthErrorDescription",
                "oauthErrorDesc",
                "oauth_description",
                "reason");
        if (!hasText(reasonMessage)) {
            reasonMessage = firstText(upstream, "message");
        }
        if (!hasText(reasonMessage) && details != null && !(details instanceof Map<?, ?>)) {
            reasonMessage = asText(details);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("traceId", hasText(traceId) ? traceId : "");
        if (hasText(reasonCode)) {
            out.put("reasonCode", reasonCode);
        } else {
            out.put("reasonCode", "");
        }
        if (hasText(reasonMessage)) {
            out.put("reasonMessage", reasonMessage);
        } else {
            out.put("reasonMessage", "");
        }
        out.put("upstream", upstream);
        out.put("context", context);

        if (log.isDebugEnabled()) {
            log.debug("error.details 归一化完成: traceId={}, reasonCode={}, upstreamKeys={}, contextKeys={}",
                    out.get("traceId"), out.get("reasonCode"), upstream.keySet(), context.keySet());
        }

        return out;
    }

    private static Map<String, Object> normalizeUpstream(Map<String, Object> source, Map<String, Object> upstreamSource) {
        Map<String, Object> out = new LinkedHashMap<>();

        String service = firstText(upstreamSource, "service", "upstreamService", "upstream_service");
        if (!hasText(service)) {
            service = firstText(source, "upstreamService", "upstream_service");
        }
        if (hasText(service)) {
            out.put("service", service);
        }

        Integer status = firstInteger(upstreamSource, "status", "upstreamStatus", "upstream_status");
        if (status == null) {
            status = firstInteger(source, "upstreamStatus", "upstream_status");
        }
        if (status != null) {
            out.put("status", status);
        }

        String code = firstText(upstreamSource, "code", "upstreamCode", "upstream_code", "oauthErrorCode", "oauth_code", "error_code");
        if (!hasText(code)) {
            code = firstText(source, "upstreamCode", "upstream_code", "oauthErrorCode", "oauth_code", "error_code");
        }
        if (hasText(code)) {
            out.put("code", code);
        }

        String message = firstText(upstreamSource,
                "message",
                "upstreamMessage", "upstream_message",
                "upstreamDescription", "upstream_description",
                "oauthErrorDescription", "oauthErrorDesc", "oauth_description");
        if (!hasText(message)) {
            message = firstText(source,
                    "upstreamMessage", "upstream_message",
                    "upstreamDescription", "upstream_description",
                    "oauthErrorDescription", "oauthErrorDesc", "oauth_description");
        }
        if (hasText(message)) {
            out.put("message", message);
        }

        Object bodySnippet = firstObject(upstreamSource, "bodySnippet", "upstreamBodySnippet", "upstream_body_snippet");
        if (bodySnippet == null) {
            bodySnippet = firstObject(source, "upstreamBodySnippet", "upstream_body_snippet");
        }
        if (bodySnippet != null) {
            out.put("bodySnippet", bodySnippet);
        }

        upstreamSource.forEach((k, v) -> {
            if (!UPSTREAM_RESERVED_KEYS.contains(k) && v != null) {
                out.putIfAbsent(k, v);
            }
        });

        return out;
    }

    private static Map<String, Object> normalizeContext(Map<String, Object> source, Map<String, Object> contextSource) {
        Map<String, Object> out = new LinkedHashMap<>();
        contextSource.forEach((k, v) -> {
            if (v != null) {
                out.put(k, v);
            }
        });
        source.forEach((k, v) -> {
            if (!ROOT_RESERVED_KEYS.contains(k) && v != null) {
                out.putIfAbsent(k, v);
            }
        });
        return out;
    }

    private static String firstText(Map<String, Object> details, String... keys) {
        if (details == null || keys == null) {
            return "";
        }
        for (String key : keys) {
            if (!hasText(key)) {
                continue;
            }
            String value = asText(details.get(key));
            if (hasText(value)) {
                return value;
            }
        }
        return "";
    }

    private static Integer firstInteger(Map<String, Object> details, String... keys) {
        if (details == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            if (!hasText(key)) {
                continue;
            }
            Object raw = details.get(key);
            if (raw == null) {
                continue;
            }
            if (raw instanceof Number number) {
                return number.intValue();
            }
            String value = asText(raw);
            if (!hasText(value)) {
                continue;
            }
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException ignored) {
                // 忽略不可解析值，继续尝试下一个字段
            }
        }
        return null;
    }

    private static Object firstObject(Map<String, Object> details, String... keys) {
        if (details == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            if (!hasText(key)) {
                continue;
            }
            Object raw = details.get(key);
            if (raw != null) {
                return raw;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asStringKeyMap(Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!(value instanceof Map<?, ?> map)) {
            return out;
        }
        map.forEach((k, v) -> out.put(String.valueOf(k), v));
        return out;
    }

    private static String asText(Object value) {
        if (Objects.isNull(value)) {
            return "";
        }
        return String.valueOf(value).trim();
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }
}
