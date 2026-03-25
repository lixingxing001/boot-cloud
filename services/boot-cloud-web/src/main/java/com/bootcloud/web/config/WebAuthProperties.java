package com.bootcloud.web.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * boot-cloud-web 认证包装层配置。
 *
 * <p>该配置只保留通用 BFF 能力需要的最小集合：</p>
 * <ul>
 *   <li>短期票据的加密参数。</li>
 *   <li>设备标识签名密钥。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.web.auth")
public class WebAuthProperties {

    /**
     * 短期票据的加密参数。
     */
    private TicketConfig ticket = new TicketConfig();

    /**
     * 设备标识签名参数。
     */
    private DeviceConfig device = new DeviceConfig();

    @Data
    public static class DeviceConfig {

        /**
         * 设备标识签名密钥。
         *
         * <p>建议放到配置中心或密钥系统，长度至少 32 字节。</p>
         */
        private String tokenSecret;
    }

    @Data
    public static class TicketConfig {

        /**
         * AES-GCM 对称密钥，使用 Base64 编码。
         */
        private String aesKeyBase64;

        /**
         * 票据有效期，单位秒。
         */
        private long ticketTtlSeconds = 60;
    }
}
