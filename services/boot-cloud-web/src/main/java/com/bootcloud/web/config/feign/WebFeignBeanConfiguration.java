package com.bootcloud.web.config.feign;

import com.bootcloud.auth.starter.config.AuthClientProperties;
import com.bootcloud.common.feign.DynamicFeignClientFactory;
import com.bootcloud.common.feign.api.AuthOAuthApi;
import com.bootcloud.common.feign.api.BaseTenantAdminApi;
import com.bootcloud.web.config.BootCloudWebServiceBindingsProperties;
import com.bootcloud.web.config.UpstreamProperties;
import com.bootcloud.web.feign.WebFeignClients;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.util.StringUtils;

/**
 * boot-cloud-web Feign 动态选择 Bean 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot.cloud.auth.client.base-url 支持服务名与直连 URL。</li>
 *   <li>最终通过 DynamicFeignClientFactory 按 baseUrl 自动选择 LB 或 direct。</li>
 * </ul>
 */
@Slf4j
@Configuration
@EnableConfigurationProperties({UpstreamProperties.class, BootCloudWebServiceBindingsProperties.class})
public class WebFeignBeanConfiguration {

    @Bean
    public DynamicFeignClientFactory dynamicFeignClientFactory() {
        return new DynamicFeignClientFactory();
    }

    @Bean
    @Primary
    public AuthOAuthApi authOAuthApi(
            DynamicFeignClientFactory factory,
            WebFeignClients.AuthLoadBalancedClient lb,
            WebFeignClients.AuthDirectClient direct,
            AuthClientProperties props
    ) {
        String baseUrl = props == null ? null : props.getBaseUrl();
        log.info("boot-cloud-web 绑定 AuthOAuthApi: baseUrl={}", baseUrl);
        return factory.create(
                AuthOAuthApi.class,
                () -> props == null ? null : props.getBaseUrl(),
                lb,
                direct,
                "boot-cloud-auth"
        );
    }

    @Bean
    @Primary
    public BaseTenantAdminApi baseTenantAdminApi(
            DynamicFeignClientFactory factory,
            WebFeignClients.BaseTenantAdminLoadBalancedClient lb,
            WebFeignClients.BaseTenantAdminDirectClient direct,
            BootCloudWebServiceBindingsProperties bindingsProperties
    ) {
        String serviceName = resolveServiceName(
                bindingsProperties == null ? null : bindingsProperties.getBaseService(),
                "boot-cloud-base"
        );
        String baseUrl = resolveBaseUrl(
                bindingsProperties == null ? null : bindingsProperties.getBaseService(),
                "http://boot-cloud-base"
        );
        log.info("boot-cloud-web 绑定 BaseTenantAdminApi: baseUrl={}", baseUrl);
        return factory.create(BaseTenantAdminApi.class, () -> baseUrl, lb, direct, serviceName);
    }

    private static String resolveServiceName(BootCloudWebServiceBindingsProperties.ServiceBinding binding, String fallback) {
        if (binding == null || !StringUtils.hasText(binding.getServiceName())) {
            return fallback;
        }
        return binding.getServiceName().trim();
    }

    private static String resolveBaseUrl(BootCloudWebServiceBindingsProperties.ServiceBinding binding, String fallback) {
        if (binding == null || !StringUtils.hasText(binding.getBaseUrl())) {
            return fallback;
        }
        return binding.getBaseUrl().trim();
    }
}
