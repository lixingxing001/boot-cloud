package com.bootcloud.common.security.internal;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 内部调用鉴权配置。
 *
 * <p>该配置用于保护 {@code /internal/**} 路径，只暴露 HMAC 与静态密钥两类基础能力。</p>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.internal-auth")
public class InternalAuthProperties {

    /** 内部服务共享密钥。 */
    private String internalServiceSecret;

    /** 内部服务静态密钥头名称。 */
    private String internalServiceHeader = "X-Internal-Service-Token";

    /** 是否启用 HMAC 验签。 */
    private boolean internalHmacEnabled = true;

    /** 是否允许旧版静态密钥头兜底。 */
    private boolean acceptLegacyServiceToken = true;

    /** HMAC 时间戳容忍窗口，单位秒。 */
    private long internalHmacSkewSeconds = 300L;

    /** 允许调用的服务名白名单。 */
    private List<String> internalAllowedServices = new ArrayList<>();
}
