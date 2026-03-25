package com.bootcloud.web.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * boot-cloud-web（BFF）后台管理端登录相关配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>后台管理端也强制走 BFF：前端不持有 client_secret。</li>
 *   <li>boot-cloud-web 代持一个“后台专用 OAuth client”，用于调用 boot-cloud-auth 的 /oauth/token。</li>
 *   <li>建议后台专用 client 与用户端 client 分离（最小权限），避免误配置导致 scope 提权。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.web.admin-auth")
public class AdminAuthProperties {

    /**
     * 后台专用 OAuth2 client_id（示例：boot-cloud-admin-web）。
     */
    private String clientId = "boot-cloud-admin-web";

    /**
     * 后台专用 OAuth2 client_secret（明文）。
     *
     * <p>安全建议：</p>
     * <ul>
     *   <li>只放在 Nacos/密钥系统里，不要提交到 Git。</li>
     *   <li>生产环境建议使用更强密码，并限制 boot-cloud-web 的调用来源（仅网关/内网）。</li>
     * </ul>
     */
    private String clientSecret;

    /**
     * 是否使用 HTTP Basic 传递 client 认证信息。
     *
     * <p>说明：boot-cloud-auth 同时兼容 Basic 与 form，这里默认启用 Basic。</p>
     */
    private boolean useBasicAuth = true;

    /**
     * 后台多会话 deviceId cookie 名称。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>同一个管理员账号允许多端同时在线，需要用 deviceId 区分会话。</li>
     *   <li>deviceId 只在 BFF（boot-cloud-web）与 boot-cloud-auth 之间传递，前端无需感知也不需要参与生成。</li>
     * </ul>
     */
    private String deviceIdCookieName = "BOOT_CLOUD_ADMIN_DEVICE_ID";

    /**
     * deviceId cookie 有效期（秒）。
     *
     * <p>建议与 refresh_token TTL 接近，默认 30 天。</p>
     */
    private long deviceIdCookieMaxAgeSeconds = 2592000;

    /**
     * deviceId cookie Path。
     *
     * <p>默认根路径，保证后台任意页面都能携带该 cookie。</p>
     */
    private String deviceIdCookiePath = "/";

    /**
     * deviceId cookie Domain。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认不设置，表示使用当前请求域名。</li>
     *   <li>如果后台前端与网关/BFF 需要在同一主域名下共享 cookie，可显式配置为父域，例如 {@code .example.com}。</li>
     * </ul>
     */
    private String deviceIdCookieDomain;

    /**
     * SameSite 属性。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>默认 Lax 适合同站点调用。</li>
     *   <li>若后台前端与网关/BFF 不同域，且需要跨站携带 cookie，则可改为 None，并同时开启 secure。</li>
     * </ul>
     */
    private String deviceIdCookieSameSite = "Lax";

    /**
     * 是否设置 Secure 属性（https 场景建议 true）。
     */
    private boolean deviceIdCookieSecure = false;
}
