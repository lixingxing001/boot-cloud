package com.bootcloud.auth.starter.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 认证中心客户端配置。
 *
 * <p>该配置供网关、BFF、资源服务等调用方复用，避免重复封装鉴权请求。</p>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.auth.client")
public class AuthClientProperties {

    /**
     * 认证中心基础地址。
     */
    private String baseUrl = "http://boot-cloud-auth";

    /**
     * OAuth2 token 端点路径。
     */
    private String tokenPath = "/oauth/token";

    /**
     * OAuth2 token introspection 端点路径。
     */
    private String introspectPath = "/oauth/check_token";

    /**
     * OAuth2 token revocation 端点路径。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于服务端登出：撤销 access_token 与 refresh_token。</li>
     *   <li>典型调用方：boot-cloud-web（BFF）代持 client_secret 后调用 boot-cloud-auth 的 /oauth/revoke。</li>
     * </ul>
     */
    private String revokePath = "/oauth/revoke";

    /**
     * 调用认证中心时使用的 OAuth2 client_id。
     */
    private String clientId;

    /**
     * 调用认证中心时使用的 OAuth2 client_secret。
     */
    private String clientSecret;

    /**
     * 租户头（默认与网关/服务端保持一致）。
     */
    private String tenantHeaderName = "X-Tenant-Id";

    /**
     * 是否使用 HTTP Basic 方式传 client 认证信息。
     */
    private boolean useBasicAuth = true;

    /**
     * 请求超时（仅对部分 client 生效）。
     */
    private Duration timeout = Duration.ofSeconds(3);
}

