package com.bootcloud.auth.starter.core;

import org.springframework.util.StringUtils;

/**
 * 认证中心调用运行时配置。
 *
 * <p>该对象不直接暴露为 {@code @ConfigurationProperties}，便于网关或 BFF 在运行时做二次桥接。</p>
 */
public class AuthClientConfig {

    private final String baseUrl;
    private final String tokenPath;
    private final String introspectPath;
    private final String clientId;
    private final String clientSecret;
    private final String tenantHeaderName;
    private final boolean useBasicAuth;

    public AuthClientConfig(
            String baseUrl,
            String tokenPath,
            String introspectPath,
            String clientId,
            String clientSecret,
            String tenantHeaderName,
            boolean useBasicAuth
    ) {
        this.baseUrl = normalizeBaseUrl(baseUrl);
        this.tokenPath = normalizePath(tokenPath, "/oauth/token");
        this.introspectPath = normalizePath(introspectPath, "/oauth/check_token");
        // 对关键文本做 trim，避免环境变量带空格时破坏 Basic 认证与表单参数解析。
        this.clientId = normalizeText(clientId);
        this.clientSecret = normalizeText(clientSecret);
        this.tenantHeaderName = StringUtils.hasText(tenantHeaderName) ? tenantHeaderName.trim() : "X-Tenant-Id";
        this.useBasicAuth = useBasicAuth;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getTokenPath() {
        return tokenPath;
    }

    public String getIntrospectPath() {
        return introspectPath;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getTenantHeaderName() {
        return tenantHeaderName;
    }

    public boolean isUseBasicAuth() {
        return useBasicAuth;
    }

    public String tokenUrl() {
        return baseUrl + tokenPath;
    }

    public String introspectUrl() {
        return baseUrl + introspectPath;
    }

    @Override
    public String toString() {
        return "AuthClientConfig{" +
                "baseUrl='" + baseUrl + '\'' +
                ", tokenPath='" + tokenPath + '\'' +
                ", introspectPath='" + introspectPath + '\'' +
                ", clientId='" + clientId + '\'' +
                ", tenantHeaderName='" + tenantHeaderName + '\'' +
                ", useBasicAuth=" + useBasicAuth +
                '}';
    }

    private static String normalizeBaseUrl(String raw) {
        if (!StringUtils.hasText(raw)) {
            return "http://boot-cloud-auth";
        }
        String s = raw.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static String normalizePath(String raw, String fallback) {
        String s = StringUtils.hasText(raw) ? raw.trim() : fallback;
        if (!s.startsWith("/")) {
            s = "/" + s;
        }
        return s;
    }

    private static String normalizeText(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String s = raw.trim();
        return StringUtils.hasText(s) ? s : null;
    }
}

