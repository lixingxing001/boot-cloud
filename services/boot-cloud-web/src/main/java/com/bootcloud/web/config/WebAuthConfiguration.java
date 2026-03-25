package com.bootcloud.web.config;

import com.bootcloud.web.core.ticket.AesGcmTicketCipher;
import com.bootcloud.web.core.ticket.TicketCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.util.Base64;

@Configuration
@EnableConfigurationProperties({
        WebAuthProperties.class,
        AdminAuthProperties.class,
        UserAuthProperties.class,
        ClientVersionProperties.class
})
public class WebAuthConfiguration {

    private static final Logger log = LoggerFactory.getLogger(WebAuthConfiguration.class);

    @Bean
    public TicketCipher ticketCipher(WebAuthProperties props) {
        String keyB64 = props.getTicket().getAesKeyBase64();
        byte[] key;
        if (StringUtils.hasText(keyB64)) {
            try {
                key = Base64.getDecoder().decode(keyB64.trim());
            } catch (Exception e) {
                throw new IllegalArgumentException("boot.cloud.web.auth.ticket.aes-key-base64 不是有效的 Base64 字符串", e);
            }
        } else {
            // 开发联调兜底：不配置时生成临时 key，服务重启后旧票据会失效。
            key = new byte[32];
            new SecureRandom().nextBytes(key);
            log.warn("未配置 boot.cloud.web.auth.ticket.aes-key-base64，已生成临时 key，适用于开发联调");
            log.warn("建议把以下 key 写入 Nacos：boot.cloud.web.auth.ticket.aes-key-base64={}", Base64.getEncoder().encodeToString(key));
        }
        return new AesGcmTicketCipher(key);
    }
}
