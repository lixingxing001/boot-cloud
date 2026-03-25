package com.bootcloud.common.feign;

/**
 * baseUrl 模式。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>DISCOVERY：通过服务发现调用，常见配置是 http://boot-cloud-risk 这类“服务名 URL”。</li>
 *   <li>DIRECT：通过固定地址直连，常见配置是 http://localhost:9540 或 https://risk.xxx.com。</li>
 * </ul>
 */
public enum ServiceUrlMode {
    DISCOVERY,
    DIRECT
}

