package com.bootcloud.web.core.util;

import com.bootcloud.web.config.WebAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * deviceId Cookie 服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一封装 deviceId 的签名、读取、旧 cookie 升级逻辑。</li>
 *   <li>签名密钥优先读取 {@code boot.cloud.web.auth.device.token-secret}。</li>
 *   <li>如果未配置，则优先回退到 ticket AES key；两者都没有时生成临时密钥，仅适用于开发联调。</li>
 * </ul>
 */
@Slf4j
@Component
public class DeviceIdCookieService {

    private final String deviceTokenSecret;

    public DeviceIdCookieService(WebAuthProperties authProperties) {
        this.deviceTokenSecret = resolveDeviceTokenSecret(authProperties);
    }

    public String readDeviceId(HttpServletRequest request, String cookieName, long maxAgeSeconds) {
        return DeviceIdCookieUtil.resolveDeviceId(request, cookieName, maxAgeSeconds, deviceTokenSecret);
    }

    public String getOrCreateDeviceId(
            HttpServletRequest request,
            HttpServletResponse response,
            String cookieName,
            long maxAgeSeconds,
            String path,
            String sameSite,
            boolean secure,
            String domain
    ) {
        return DeviceIdCookieUtil.getOrCreateDeviceId(
                request,
                response,
                cookieName,
                maxAgeSeconds,
                path,
                sameSite,
                secure,
                domain,
                deviceTokenSecret
        );
    }

    private String resolveDeviceTokenSecret(WebAuthProperties authProperties) {
        String configured = authProperties != null
                && authProperties.getDevice() != null
                ? authProperties.getDevice().getTokenSecret()
                : null;
        if (StringUtils.hasText(configured)) {
            return configured.trim();
        }

        String ticketKey = authProperties != null
                && authProperties.getTicket() != null
                ? authProperties.getTicket().getAesKeyBase64()
                : null;
        if (StringUtils.hasText(ticketKey)) {
            log.warn("未配置 boot.cloud.web.auth.device.token-secret，当前回退复用 ticket AES key 作为 deviceToken 签名密钥");
            return "ticket:" + ticketKey.trim();
        }

        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String generated = Base64.getEncoder().encodeToString(random);
        log.warn("未配置 boot.cloud.web.auth.device.token-secret 且 ticket AES key 为空，已生成临时 deviceToken 密钥，仅适用于开发联调");
        log.warn("建议把以下配置写入 Nacos：boot.cloud.web.auth.device.token-secret={}", generated);
        return generated;
    }
}
