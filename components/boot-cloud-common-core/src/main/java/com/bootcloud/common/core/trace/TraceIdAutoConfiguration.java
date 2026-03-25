package com.bootcloud.common.core.trace;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * TraceId 自动配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>Servlet：注册 TraceIdServletFilter，写入 MDC，并回写响应头。</li>
 *   <li>内部调用：为 RestTemplate 注入 TraceId 透传拦截器。</li>
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(TraceProperties.class)
@ConditionalOnProperty(prefix = "boot.cloud.trace", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TraceIdAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(TraceIdAutoConfiguration.class);

    @Bean
    @ConditionalOnClass(RestTemplate.class)
    public TraceIdRestTemplateBeanPostProcessor traceIdRestTemplateBeanPostProcessor(TraceProperties props) {
        return new TraceIdRestTemplateBeanPostProcessor(props);
    }

    @Bean
    @ConditionalOnClass(WebClient.Builder.class)
    public TraceIdWebClientBuilderBeanPostProcessor traceIdWebClientBuilderBeanPostProcessor(TraceProperties props) {
        return new TraceIdWebClientBuilderBeanPostProcessor(props);
    }

    /**
     * Servlet 场景的 Filter 注册。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>必须放到独立配置类里，避免 WebFlux 服务（例如 boot-cloud-gateway）在缺少 servlet 依赖时发生 NoClassDefFoundError。</li>
     * </ul>
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = Type.SERVLET)
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    static class ServletTraceIdConfiguration {

        private static final Logger servletLog = LoggerFactory.getLogger(ServletTraceIdConfiguration.class);

        @Bean
        @ConditionalOnClass(name = "org.springframework.boot.web.servlet.FilterRegistrationBean")
        public org.springframework.boot.web.servlet.FilterRegistrationBean<TraceIdServletFilter> traceIdServletFilter(TraceProperties props) {
            org.springframework.boot.web.servlet.FilterRegistrationBean<TraceIdServletFilter> bean =
                    new org.springframework.boot.web.servlet.FilterRegistrationBean<>();
            bean.setFilter(new TraceIdServletFilter(props));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 5);
            bean.setName("traceIdServletFilter");

            if (props != null && props.isStartupLog()) {
                servletLog.info("TraceIdServletFilter 已启用，headerName={}, echoResponseHeader={}", props.getHeaderName(), props.isEchoResponseHeader());
            }
            return bean;
        }
    }
}
