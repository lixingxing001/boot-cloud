package com.bootcloud.auth.starter.autoconfig;

import com.bootcloud.auth.starter.config.AuthClientProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * 认证中心客户端属性自动装配。
 */
@AutoConfiguration(before = {AuthMvcClientAutoConfiguration.class, AuthReactiveClientAutoConfiguration.class})
@EnableConfigurationProperties(AuthClientProperties.class)
public class AuthClientPropertiesAutoConfiguration {
}
