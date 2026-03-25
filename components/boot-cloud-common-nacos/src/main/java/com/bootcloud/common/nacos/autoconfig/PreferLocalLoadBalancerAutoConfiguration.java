package com.bootcloud.common.nacos.autoconfig;

import com.bootcloud.common.nacos.lb.PreferLocalLoadBalancerProperties;
import com.bootcloud.common.nacos.lb.PreferLocalFirstLoadBalancer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.EmptyResponse;
import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClients;
import org.springframework.cloud.loadbalancer.core.ReactorLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;

/**
 * 本机优先 LoadBalancer 自动装配。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于本地联调：当本机也注册了服务实例时，优先把请求路由到本机实例。</li>
 *   <li>对所有通过 Spring Cloud LoadBalancer 发起的服务名调用生效，例如 http://boot-cloud-auth。</li>
 *   <li>开关：{@code boot.cloud.lb.prefer-local.enabled=true}</li>
 * </ul>
 */
@AutoConfiguration
@ConditionalOnClass(name = "org.springframework.cloud.loadbalancer.core.ReactorLoadBalancer")
@LoadBalancerClients(defaultConfiguration = PreferLocalLoadBalancerAutoConfiguration.PreferLocalLoadBalancerConfiguration.class)
public class PreferLocalLoadBalancerAutoConfiguration {

    @Slf4j
    @Configuration
    @EnableConfigurationProperties(PreferLocalLoadBalancerProperties.class)
    @ConditionalOnProperty(prefix = "boot.cloud.lb.prefer-local", name = "enabled", havingValue = "true")
    @Conditional(PreferLocalLoadBalancerNotExcludedCondition.class)
    public static class PreferLocalLoadBalancerConfiguration {

        /**
         * 为每个服务名创建独立的 LoadBalancer（Spring Cloud LoadBalancer 的标准做法）。
         *
         * <p>说明：</p>
         * <ul>
         *   <li>该 Bean 会在每个 serviceId 的子上下文中创建一次。</li>
         *   <li>需要懒加载 supplier，避免初始化阶段递归创建导致启动失败。</li>
         * </ul>
         */
        @Bean
        public ReactorLoadBalancer<ServiceInstance> reactorServiceInstanceLoadBalancer(
                Environment env,
                LoadBalancerClientFactory factory,
                PreferLocalLoadBalancerProperties props
        ) {
            String serviceId = env.getProperty(LoadBalancerClientFactory.PROPERTY_NAME);
            if (serviceId == null || serviceId.isBlank()) {
                log.warn("LoadBalancer 未获取到 serviceId，返回 EmptyResponse");
                return request -> Mono.just(new EmptyResponse());
            }

            ObjectProvider<ServiceInstanceListSupplier> supplierProvider =
                    factory.getLazyProvider(serviceId, ServiceInstanceListSupplier.class);
            return new PreferLocalFirstLoadBalancer(supplierProvider, serviceId, props);
        }
    }
}
