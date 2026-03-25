package com.bootcloud.gateway.config;

import com.bootcloud.common.core.trace.TraceProperties;
import com.bootcloud.gateway.core.filter.TraceIdGlobalFilter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.cloud.client.loadbalancer.reactive.LoadBalancedExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * 网关基础 Bean 配置。
 */
@Configuration
@EnableConfigurationProperties({
        GatewayProperties.class,
        GatewayRiskShieldProperties.class,
        GatewayRiskSyncProperties.class,
        GatewayInternalAuthProperties.class,
        GatewayCorsProperties.class,
        GatewayPreferLocalLoadBalancerProperties.class,
        SecurityPublicPathsProperties.class
})
public class GatewayConfiguration {

    /**
     * LoadBalanced WebClient：支持用服务名调用（http://boot-cloud-auth / http://boot-cloud-base）。
     *
     * <p>说明：Gateway 是 WebFlux 栈，因此这里使用 WebClient。</p>
     */
    @Bean
    public WebClient loadBalancedWebClient(WebClient.Builder builder, LoadBalancedExchangeFilterFunction lb) {
        // 说明：
        // - WebClient.Builder 会被 boot-cloud-common-core 自动注入 TraceId 透传 filter
        // - 这里额外叠加 load balancer filter，支持通过服务名调用
        return builder.filter(lb).build();
    }

    @Bean
    public TraceIdGlobalFilter traceIdGlobalFilter(TraceProperties props) {
        return new TraceIdGlobalFilter(props);
    }
}
