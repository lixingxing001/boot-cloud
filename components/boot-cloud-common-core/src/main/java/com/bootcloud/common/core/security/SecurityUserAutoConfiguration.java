package com.bootcloud.common.core.security;

import jakarta.servlet.Filter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.context.annotation.Bean;

/**
 * SecurityUser 自动配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>在 Servlet Web 应用中自动注册 {@link SecurityUserContextFilter}。</li>
 *   <li>该 Filter 负责从网关注入的 Header 初始化 ThreadLocal 上下文。</li>
 *   <li>后续当服务升级为标准资源服务时，业务代码也可通过 SecurityUserUtils 从 SecurityContext 读取信息。</li>
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(SecurityUserProperties.class)
@ConditionalOnWebApplication(type = Type.SERVLET)
@ConditionalOnClass(Filter.class)
@ConditionalOnProperty(prefix = "boot.cloud.security.user", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityUserAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SecurityUserAutoConfiguration.class);

    /**
     * 注册用户上下文 Filter。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>Filter 需要在 Controller 执行前生效。</li>
     *   <li>我们设置为偏靠前，保证业务层可随时读取。</li>
     * </ul>
     */
    @Order(Ordered.HIGHEST_PRECEDENCE + 20)
    @Bean
    public FilterRegistrationBean<SecurityUserContextFilter> securityUserContextFilter(SecurityUserProperties properties) {
        FilterRegistrationBean<SecurityUserContextFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(new SecurityUserContextFilter(properties));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        bean.setName("securityUserContextFilter");

        log.info("SecurityUserContextFilter 已启用，userIdHeader={}, tenantIdHeader={}, clientIdHeader={}, scopeHeader={}",
                properties.getUserIdHeader(), properties.getTenantIdHeader(), properties.getClientIdHeader(), properties.getScopeHeader());
        return bean;
    }
}
