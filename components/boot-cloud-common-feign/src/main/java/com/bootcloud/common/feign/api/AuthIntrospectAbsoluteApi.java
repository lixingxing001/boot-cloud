package com.bootcloud.common.feign.api;

import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

/**
 * 绝对自省 URL 调用接口。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于 url 直接配置为完整 introspectionUri 的场景，例如 http://localhost:9999/oauth/check_token。</li>
 *   <li>因此方法上不再拼接 path，避免重复追加导致 404。</li>
 * </ul>
 */
public interface AuthIntrospectAbsoluteApi {

    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String introspect(@RequestHeader Map<String, String> headers, @RequestBody MultiValueMap<String, String> form);

    /**
     * 以“表单字符串”方式调用 /oauth/check_token。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于解决部分环境下 {@code MultiValueMap} 未按表单编码写入请求体，导致服务端解析不到 {@code token} 参数的问题。</li>
     *   <li>body 形如：{@code token=xxx}，调用方需要自行对 value 做 URL 编码（UTF-8）。</li>
     * </ul>
     */
    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    String introspectRaw(@RequestHeader Map<String, String> headers, @RequestBody String body);
}
