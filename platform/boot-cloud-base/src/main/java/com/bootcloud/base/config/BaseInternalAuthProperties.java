package com.bootcloud.base.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * boot-cloud-base 内部接口鉴权配置（内部密钥头）。
 *
 * <ul>
 *   <li>本配置用于保护 {@code /internal/admin/**} 管理接口，避免误暴露到公网后被滥用。</li>
 *   <li>与网关侧的内部鉴权配置保持一致，便于复用同一套密钥。</li>
 *   <li>{@code /internal/tenant/resolve} 供网关解析租户使用，不在本拦截器保护范围内。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.internal-auth")
public class BaseInternalAuthProperties {

    /**
     * 内部密钥（建议放 Nacos，并限制配置权限）。
     *
     * <p>当为空时：管理接口默认直接拒绝（fail-closed），避免“忘配密钥”导致裸奔。</p>
     */
    private String internalServiceSecret;

    /**
     * 内部密钥的 Header 名称。
     */
    private String internalServiceHeader = "X-Internal-Service-Token";

    /**
     * 是否启用 HMAC 验签（X-Service-Name + X-Internal-Timestamp + X-Internal-Sign）。
     */
    private boolean internalHmacEnabled = true;

    /**
     * 是否允许旧版静态密钥头兜底。
     */
    private boolean acceptLegacyServiceToken = true;

    /**
     * HMAC 时间戳容忍窗口（秒）。
     */
    private long internalHmacSkewSeconds = 300L;

    /**
     * 允许调用的 serviceName 白名单。
     *
     * <p>为空时不做白名单限制。</p>
     */
    private List<String> internalAllowedServices = new ArrayList<>();
}

