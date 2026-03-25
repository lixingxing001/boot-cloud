package com.bootcloud.web.core.util;

import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * 日志安全工具：脱敏与截断。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>避免把 access_token、refresh_token、password、client_secret 写入日志与错误详情。</li>
 *   <li>只提供“片段信息”，用于定位问题，不用于业务处理。</li>
 * </ul>
 */
public final class LogSafeUtil {

    private LogSafeUtil() {
    }

    private static final Pattern[] SENSITIVE_JSON_FIELDS = new Pattern[]{
            Pattern.compile("(\"access_token\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\"refresh_token\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\"id_token\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\"token\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\"password\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\"client_secret\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE)
    };

    public static String sanitizeAndTruncate(String raw, int maxChars) {
        if (!StringUtils.hasText(raw)) {
            return "";
        }
        String v = raw.trim();

        // 简单脱敏：仅处理常见 JSON 字段，避免误伤其它内容
        for (Pattern p : SENSITIVE_JSON_FIELDS) {
            v = p.matcher(v).replaceAll("$1****$3");
        }

        // 统一换行，避免日志跨行影响检索
        v = v.replace("\r", "\\r").replace("\n", "\\n");

        if (maxChars <= 0 || v.length() <= maxChars) {
            return v;
        }
        return v.substring(0, maxChars) + "...(truncated)";
    }
}

