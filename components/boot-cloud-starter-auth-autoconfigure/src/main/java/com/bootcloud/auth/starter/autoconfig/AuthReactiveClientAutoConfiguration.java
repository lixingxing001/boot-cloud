package com.bootcloud.auth.starter.autoconfig;

import com.bootcloud.auth.starter.client.reactive.AuthReactiveIntrospectClient;
import com.bootcloud.auth.starter.config.AuthClientProperties;
import com.bootcloud.auth.starter.core.AuthClientConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.net.http.HttpClient;

@AutoConfiguration
@EnableConfigurationProperties(AuthClientProperties.class)
@ConditionalOnClass(name = "org.springframework.web.reactive.function.client.WebClient")
public class AuthReactiveClientAutoConfiguration {

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
    public AuthReactiveIntrospectClient evmAuthReactiveIntrospectClient(
            ObjectProvider<WebClient> webClientProvider,
            AuthClientConfig config,
            AuthClientProperties props
    ) {
        WebClient wc = webClientProvider.getIfAvailable(() -> buildDefaultWebClient(props));
        return new AuthReactiveIntrospectClient(wc, config);
    }

    private static WebClient buildDefaultWebClient(AuthClientProperties props) {
        Duration timeout = props == null || props.getTimeout() == null
                ? Duration.ofSeconds(3)
                : props.getTimeout();
        long timeoutMs = Math.max(500L, timeout.toMillis());
        long connectTimeoutMs = Math.min(timeoutMs, 2000L);

        // 说明：
        // starter 模块不强依赖 reactor-netty，这里使用 JDK HttpClient 设置连接超时。
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .build();
        return WebClient.builder()
                .clientConnector(new JdkClientHttpConnector(httpClient))
                .build();
    }
}

