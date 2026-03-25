package com.bootcloud.auth.config;

import cn.dev33.satoken.oauth2.SaOAuth2Manager;
import cn.dev33.satoken.oauth2.config.SaOAuth2Config;
import cn.dev33.satoken.oauth2.logic.SaOAuth2Util;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.infra.satoken.oauth2.SaOAuth2Template;
import com.bootcloud.auth.infra.mybatis.mapper.OAuthClientMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Sa-Token OAuth2 相关配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>Sa-Token OAuth2 的入口是静态工具类 {@link SaOAuth2Util} / {@link SaOAuth2Manager}。</li>
 *   <li>因此这里需要在 Spring 启动时把“自定义模板”注入进去，才能做到：DB client + BCrypt secret + 多租户 Key。</li>
 * </ul>
 */
@Configuration
public class SaTokenOAuth2Configuration {

    @Bean
    public SaOAuth2Template saOAuth2Template(
            OAuthClientMapper clientMapper,
            PasswordEncoder passwordEncoder,
            AuthServerProperties properties,
            StringRedisTemplate redis,
            ObjectMapper mapper
    ) {
        return new SaOAuth2Template(clientMapper, passwordEncoder, properties, redis, mapper);
    }

    @Primary
    @Bean
    public SaOAuth2Config saOAuth2Config(AuthServerProperties properties) {
        // 说明：本项目对外暴露的 /oauth/* 端点会自行组织参数与响应，不依赖 SaOAuth2Handle 的默认“页面/重定向”行为。
        // 但 SaOAuth2Config 仍然建议显式配置，方便后续需要时接入 SaOAuth2Handle.serverRequest() 的默认路由。
        SaOAuth2Config cfg = new SaOAuth2Config();
        cfg.setIsCode(true);
        cfg.setIsPassword(true);
        cfg.setIsClient(true);
        cfg.setIsImplicit(false);
        cfg.setIsNewRefresh(!properties.isReuseRefreshToken());
        // authorization_code 的有效期同时用于 PKCE 绑定 TTL 对齐
        cfg.setCodeTimeout(Math.max(properties.getAuthorizationCodeTtlSeconds(), 1L));
        return cfg;
    }

    @Bean
    public Object saOAuth2StaticInitializer(SaOAuth2Config config, SaOAuth2Template template) {
        // 通过 Bean 初始化触发静态注入。
        SaOAuth2Manager.setConfig(config);
        SaOAuth2Util.saOAuth2Template = template;
        return new Object();
    }
}
