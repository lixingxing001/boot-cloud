package com.bootcloud.common.feign.api;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

/**
 * boot-cloud-auth OAuth2 端点。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>此接口用于调用 OAuth2 token 与 check_token。</li>
 *   <li>请求体使用 application/x-www-form-urlencoded。</li>
 *   <li>租户 Header 与 trace Header 由调用方按需传入，避免拦截器无法拿到 tenantId。</li>
 * </ul>
 */
public interface AuthOAuthApi {

    @PostMapping(value = "${boot.cloud.auth.client.token-path:${boot.cloud.auth.client.token-path:/oauth/token}}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String token(@RequestHeader Map<String, String> headers, @RequestBody MultiValueMap<String, String> form);

    /**
     * 以“表单字符串”方式调用 /oauth/token。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于解决部分环境下 {@code MultiValueMap} 未按表单编码写入请求体，导致服务端解析不到 {@code @RequestParam} 的问题。</li>
     *   <li>body 形如：{@code grant_type=xxx&client_id=xxx&username=xxx&password=xxx}</li>
     *   <li>调用方需要自行对 value 做 URL 编码（UTF-8），并自行设置 Content-Type。</li>
     * </ul>
     */
    @PostMapping(value = "${boot.cloud.auth.client.token-path:${boot.cloud.auth.client.token-path:/oauth/token}}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String tokenRaw(@RequestHeader Map<String, String> headers, @RequestBody String body);

    @PostMapping(value = "${boot.cloud.auth.client.introspect-path:${boot.cloud.auth.client.introspect-path:/oauth/check_token}}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String introspect(@RequestHeader Map<String, String> headers, @RequestBody MultiValueMap<String, String> form);

    /**
     * 以“表单字符串”方式调用 /oauth/check_token。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于规避某些环境下 MultiValueMap 编码不稳定导致服务端解析不到参数。</li>
     *   <li>body 形如：client_id=xxx&client_secret=xxx&token=xxx</li>
     * </ul>
     */
    @PostMapping(value = "${boot.cloud.auth.client.introspect-path:${boot.cloud.auth.client.introspect-path:/oauth/check_token}}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String introspectRaw(@RequestHeader Map<String, String> headers, @RequestBody String body);

    /**
     * 撤销 token（服务端登出）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>OAuth2 标准端点：/oauth/revoke</li>
     *   <li>body 形如：token=xxx&token_type_hint=refresh_token&client_id=xxx&device_id=xxx</li>
     *   <li>调用方需要自行对 value 做 URL 编码（UTF-8），并自行设置 Content-Type。</li>
     * </ul>
     */
    @PostMapping(value = "${boot.cloud.auth.client.revoke-path:${boot.cloud.auth.client.revoke-path:/oauth/revoke}}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String revokeRaw(@RequestHeader Map<String, String> headers, @RequestBody String body);

    /**
     * 列出用户已登录设备会话（服务端记录的设备列表）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该端点属于扩展 OAuth 能力：用于前端展示“登录设备管理”。</li>
     *   <li>必须具备 client 认证（Basic 或 form secret）。</li>
     * </ul>
     */
    @PostMapping(value = "/oauth/device/sessions", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String deviceSessionsRaw(@RequestHeader Map<String, String> headers, @RequestBody String body);

    /**
     * 远程登出指定设备（按 userId + deviceId 撤销该设备下的 token）。
     */
    @PostMapping(value = "/oauth/device/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String deviceRevokeRaw(@RequestHeader Map<String, String> headers, @RequestBody String body);
}
