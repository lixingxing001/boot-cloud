package com.bootcloud.common.security.autoconfig;

import com.bootcloud.common.security.internal.InternalApiInterceptor;
import com.bootcloud.common.security.internal.InternalAuthProperties;
import com.bootcloud.common.security.oauth2.OAuth2ResourceServerProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 公共安全能力自动装配。
 */
@Slf4j
@AutoConfiguration
@ConditionalOnClass(HandlerInterceptor.class)
@EnableConfigurationProperties({
        InternalAuthProperties.class,
        OAuth2ResourceServerProperties.class
})
public class CommonSecurityAutoConfiguration {

    @Bean
    public InternalApiInterceptor internalApiInterceptor(InternalAuthProperties props) {
        if (props == null) {
            log.warn("InternalApiInterceptor 初始化失败：缺少内部鉴权配置");
        }
        return new InternalApiInterceptor(props);
    }
}
