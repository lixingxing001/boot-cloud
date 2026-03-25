package com.bootcloud.gateway.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.server.ServerWebExchange;

/**
 * boot-cloud-gateway CORS 配置（WebFlux）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该过滤器会在网关层面处理 CORS 预检（OPTIONS），避免请求被转发到下游服务后再失败。</li>
 *   <li>默认不开启，需通过 {@code boot.cloud.gateway.cors.enabled=true} 显式开启。</li>
 * </ul>
 */
@Configuration
@EnableConfigurationProperties(GatewayCorsProperties.class)
@ConditionalOnProperty(prefix = "boot.cloud.gateway.cors", name = "enabled", havingValue = "true")
public class GatewayCorsConfiguration {

    @Bean
    public CorsWebFilter corsWebFilter(GatewayCorsProperties props) {
        // 说明：这里使用“动态配置源”，保证 Nacos 配置变更后无需重启即可生效。
        CorsConfigurationSource source = (ServerWebExchange exchange) -> {
            CorsConfiguration cfg = new CorsConfiguration();
            cfg.setAllowCredentials(props.isAllowCredentials());
            cfg.setAllowedOriginPatterns(props.getAllowedOriginPatterns());
            cfg.setAllowedMethods(props.getAllowedMethods());
            cfg.setAllowedHeaders(props.getAllowedHeaders());
            cfg.setExposedHeaders(props.getExposedHeaders());
            cfg.setMaxAge(props.getMaxAgeSeconds());
            return cfg;
        };
        return new CorsWebFilter(source);
    }
}

