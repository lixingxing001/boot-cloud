package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 网关侧“下游信任头”配置。
 *
 * <p>网关在边界完成鉴权后，会向下游注入用户上下文头，同时附带内部密钥头，避免被外部请求伪造。</p>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.internal-auth")
public class GatewayInternalAuthProperties {

    /**
     * 内部服务密钥。
     *
     * <p>当为空时，网关不会注入内部信任头，下游也不应信任任何来自 Header 的用户信息。</p>
     */
    private String internalServiceSecret;

    /**
     * 内部服务密钥的 header 名称。
     */
    private String internalServiceHeader = "X-Internal-Service-Token";
}

