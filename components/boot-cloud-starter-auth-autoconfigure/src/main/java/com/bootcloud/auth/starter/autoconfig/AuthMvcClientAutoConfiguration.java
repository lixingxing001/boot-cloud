package com.bootcloud.auth.starter.autoconfig;

import com.bootcloud.auth.starter.client.mvc.AuthTokenClient;
import com.bootcloud.auth.starter.config.AuthClientProperties;
import com.bootcloud.auth.starter.core.AuthClientConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@AutoConfiguration
@EnableConfigurationProperties(AuthClientProperties.class)
@ConditionalOnClass(name = "org.springframework.web.client.RestTemplate")
public class AuthMvcClientAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthClientConfig evmAuthClientConfig(AuthClientProperties props) {
        return new AuthClientConfig(
                props.getBaseUrl(),
                props.getTokenPath(),
                props.getIntrospectPath(),
                props.getClientId(),
                props.getClientSecret(),
                props.getTenantHeaderName(),
                props.isUseBasicAuth()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthTokenClient evmAuthTokenClient(ObjectProvider<RestTemplate> restTemplateProvider, AuthClientConfig config) {
        RestTemplate rt = restTemplateProvider.getIfAvailable(RestTemplate::new);
        return new AuthTokenClient(rt, config);
    }
}

