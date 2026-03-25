package com.bootcloud.auth.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/**
 * RestTemplate 配置。
 *
 * <ul>
 *   <li>{@code plainRestTemplate} 用于外部直连地址。</li>
 *   <li>{@code loadBalancedRestTemplate} 用于服务名地址。</li>
 *   <li>内部调用专用 RestTemplate 会自动注入 HMAC 鉴权头。</li>
 * </ul>
 */
@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate plainRestTemplate(RestTemplateBuilder builder) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Bean
    @LoadBalanced
    public RestTemplate loadBalancedRestTemplate(RestTemplateBuilder builder) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * 内部服务调用专用 RestTemplate。
     */
    @Bean
    public RestTemplate internalServicePlainRestTemplate(
            RestTemplateBuilder builder,
            @Value("${spring.application.name:boot-cloud-auth}") String serviceName,
            @Value("${boot.cloud.internal-auth.internal-service-secret:}") String secret,
            @Value("${boot.cloud.internal-call.debug-log:false}") boolean debugLog
    ) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(10))
                .additionalInterceptors(new InternalHmacRestTemplateInterceptor(serviceName, secret, debugLog))
                .build();
    }

    /**
     * 内部服务调用专用负载均衡 RestTemplate。
     */
    @Bean
    @LoadBalanced
    public RestTemplate internalServiceLoadBalancedRestTemplate(
            RestTemplateBuilder builder,
            @Value("${spring.application.name:boot-cloud-auth}") String serviceName,
            @Value("${boot.cloud.internal-auth.internal-service-secret:}") String secret,
            @Value("${boot.cloud.internal-call.debug-log:false}") boolean debugLog
    ) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(10))
                .additionalInterceptors(new InternalHmacRestTemplateInterceptor(serviceName, secret, debugLog))
                .build();
    }
}

