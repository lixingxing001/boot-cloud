package com.bootcloud.common.feign;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.net.URI;

/**
 * 根据 baseUrl 推断应走服务发现还是直连。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>约定：host 形如 boot-cloud-risk 且不包含点号时，大概率是服务名。</li>
 *   <li>约定：host 为 localhost，或包含点号，或是 IP 地址时，大概率是直连地址。</li>
 * </ul>
 */
@Slf4j
public final class ServiceUrlModeResolver {

    private ServiceUrlModeResolver() {
    }

    public static ServiceUrlMode resolve(String baseUrl, String targetServiceId) {
        if (!StringUtils.hasText(baseUrl)) {
            return ServiceUrlMode.DISCOVERY;
        }

        URI uri = tryParseUri(baseUrl.trim());
        if (uri == null) {
            return ServiceUrlMode.DISCOVERY;
        }

        String host = uri.getHost();
        if (!StringUtils.hasText(host)) {
            return ServiceUrlMode.DISCOVERY;
        }
        String h = host.trim();

        if ("localhost".equalsIgnoreCase(h)) {
            return ServiceUrlMode.DIRECT;
        }
        if (isIpAddress(h)) {
            return ServiceUrlMode.DIRECT;
        }
        if (h.contains(".")) {
            return ServiceUrlMode.DIRECT;
        }
        if (StringUtils.hasText(targetServiceId) && h.equalsIgnoreCase(targetServiceId.trim())) {
            return ServiceUrlMode.DISCOVERY;
        }

        return ServiceUrlMode.DISCOVERY;
    }

    private static URI tryParseUri(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        try {
            // 兼容用户只配置 host 的情况
            if (!raw.contains("://")) {
                return URI.create("http://" + raw);
            }
            return URI.create(raw);
        } catch (Exception e) {
            log.warn("解析 baseUrl 失败：baseUrl={}, msg={}", raw, e.getMessage());
            return null;
        }
    }

    private static boolean isIpAddress(String host) {
        // 简单兜底，避免引入额外依赖
        if (!StringUtils.hasText(host)) {
            return false;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
            int v;
            try {
                v = Integer.parseInt(p);
            } catch (Exception e) {
                return false;
            }
            if (v < 0 || v > 255) {
                return false;
            }
        }
        return true;
    }
}

