package com.bootcloud.gateway.config;

import com.bootcloud.gateway.core.lb.PreferLocalFirstLoadBalancer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.EmptyResponse;
import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClients;
import org.springframework.cloud.loadbalancer.core.ReactorLoadBalancer;
import org.springframework.cloud.loadbalancer.core.RoundRobinLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;

/**
 * boot-cloud-gateway 全局 LoadBalancer 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>对所有 lb:// 服务生效。</li>
 *   <li>启用后优先选择本机实例（Nacos 里 host 与本机 IP 相同）。</li>
 * </ul>
 */
@Configuration
@LoadBalancerClients(defaultConfiguration = GatewayLoadBalancerConfiguration.PreferLocalLoadBalancerConfiguration.class)
public class GatewayLoadBalancerConfiguration {

    @Slf4j
    @Configuration
    @EnableConfigurationProperties(GatewayPreferLocalLoadBalancerProperties.class)
    @ConditionalOnProperty(prefix = "boot.cloud.gateway.lb.prefer-local", name = "enabled", havingValue = "true")
    public static class PreferLocalLoadBalancerConfiguration {

        /**
         * 为每个服务名创建独立的 LoadBalancer（Spring Cloud LoadBalancer 的标准做法）。
         */
        @Bean
        public ReactorLoadBalancer<ServiceInstance> reactorServiceInstanceLoadBalancer(
                Environment env,
                LoadBalancerClientFactory factory,
                GatewayPreferLocalLoadBalancerProperties props
        ) {
            String serviceId = env.getProperty(LoadBalancerClientFactory.PROPERTY_NAME);
            if (serviceId == null || serviceId.isBlank()) {
                log.warn("LoadBalancer 未获取到 serviceId，返回 EmptyResponse");
                return request -> Mono.just(new EmptyResponse());
            }

            // 说明：
            // 这里必须保持 supplier 懒加载，避免在 Bean 初始化阶段触发子上下文递归创建，导致启动失败。
            ObjectProvider<ServiceInstanceListSupplier> supplierProvider = factory.getLazyProvider(serviceId, ServiceInstanceListSupplier.class);
            return new PreferLocalFirstLoadBalancer(supplierProvider, serviceId, props);
        }
    }
}
