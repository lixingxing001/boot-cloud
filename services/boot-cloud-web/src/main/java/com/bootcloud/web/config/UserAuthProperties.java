package com.bootcloud.web.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * boot-cloud-web（BFF）用户端会话相关配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>目标：支持同一用户账号多端同时在线，不发生“挤号”。</li>
 *   <li>实现方式：boot-cloud-web 为每个浏览器生成一个 HttpOnly deviceId cookie，并在调用 boot-cloud-auth 的 /oauth/token 与 /oauth/revoke 时透传 device_id。</li>
 *   <li>前端 JS 不需要读取 deviceId，因此使用 HttpOnly cookie 更安全。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.web.user-auth")
public class UserAuthProperties {

    /**
     * 用户端 deviceId cookie 名称。
     */
    private String deviceIdCookieName = "BOOT_CLOUD_USER_DEVICE_ID";

    /**
     * 用户端 deviceId cookie 有效期（秒），默认 30 天。
     *
     * <p>建议与 refresh_token TTL 接近。</p>
     */
    private long deviceIdCookieMaxAgeSeconds = 2592000;

    /**
     * 用户端 deviceId cookie Path。
     */
    private String deviceIdCookiePath = "/";

    /**
     * 用户端 deviceId cookie Domain。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认不设置，表示使用当前请求域名。</li>
     *   <li>如果 Web 前端、网关、BFF 处于同一主域不同子域，可配置为父域以避免同浏览器重复生成设备标识。</li>
     * </ul>
     */
    private String deviceIdCookieDomain;

    /**
     * SameSite 属性。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认 Lax 适合同站点调用。</li>
     *   <li>若前端与网关/BFF 不同域且需要跨站携带 cookie，可改为 None，并同时开启 secure。</li>
     * </ul>
     */
    private String deviceIdCookieSameSite = "Lax";

    /**
     * 是否设置 Secure 属性（https 场景建议 true）。
     */
    private boolean deviceIdCookieSecure = false;

    /**
     * 用户端租户站点手动选择器配置。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>测试环境无域名时，可通过前端下拉选择租户站点。</li>
     *   <li>选择结果以 HttpOnly Cookie 保存，刷新后仍能保持同一租户口径。</li>
     *   <li>线上建议关闭该能力，继续走域名解析租户。</li>
     * </ul>
     */
    private TenantSiteSelector tenantSiteSelector = new TenantSiteSelector();

    @Data
    public static class TenantSiteSelector {

        /**
         * 是否启用用户端租户站点选择器。
         */
        private boolean enabled = false;

        /**
         * 手动选择租户 Cookie 名称。
         */
        private String cookieName = "BOOT_CLOUD_USER_SELECTED_TENANT";

        /**
         * 手动选择租户 Cookie 有效期（秒），默认 30 天。
         */
        private long cookieMaxAgeSeconds = 2592000;

        /**
         * 手动选择租户 Cookie Path。
         */
        private String cookiePath = "/";

        /**
         * 手动选择租户 Cookie Domain。
         *
         * <p>默认不设置，使用当前请求域名。</p>
         */
        private String cookieDomain;

        /**
         * 手动选择租户 Cookie SameSite。
         *
         * <p>默认 Lax，若跨站嵌入需要带上 Cookie，可改为 None 并同时启用 Secure。</p>
         */
        private String cookieSameSite = "Lax";

        /**
         * 手动选择租户 Cookie 是否设置 Secure。
         */
        private boolean cookieSecure = false;
    }
}
