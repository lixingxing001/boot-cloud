package com.bootcloud.auth.config;

import cn.dev33.satoken.SaManager;
import cn.dev33.satoken.dao.SaTokenDao;
import cn.dev33.satoken.dao.SaTokenDaoRedisJackson;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.util.StringUtils;

/**
 * Sa-Token Redis 存储配置（独立连接：对应 nacos 的 {@code sa-token.alone-redis}）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>Sa-Token OAuth2 底层依赖 Sa-Token 的 {@link cn.dev33.satoken.dao.SaTokenDao} 来读写 Redis。</li>
 *   <li>这里显式把 Sa-Token 的 Dao 指向“独立 Redis DB”（通常为 db=7），避免污染业务 Redis。</li>
 * </ul>
 */
@Configuration
@EnableConfigurationProperties(SaTokenAloneRedisProperties.class)
public class SaTokenRedisConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SaTokenRedisConfiguration.class);

    @Bean(destroyMethod = "destroy")
    public LettuceConnectionFactory saTokenRedisConnectionFactory(SaTokenAloneRedisProperties props) {
        // 说明：兜底，避免 Nacos 配置缺失导致 NPE。
        var connectTimeout = props.getConnectTimeout() == null ? java.time.Duration.ofSeconds(1) : props.getConnectTimeout();
        var commandTimeout = props.getTimeout() == null ? java.time.Duration.ofSeconds(10) : props.getTimeout();

        // 说明：启动时打印关键信息，便于定位“连错环境”“超时过长”“Redis 不可达”等问题。
        log.info("sa-token redis init: host={}, port={}, db={}, connectTimeoutMs={}, commandTimeoutMs={}, validateConnection={}, startupCheckEnabled={}",
                props.getHost(),
                props.getPort(),
                props.getDatabase(),
                connectTimeout.toMillis(),
                commandTimeout.toMillis(),
                props.isValidateConnection(),
                props.isStartupCheckEnabled());

        RedisStandaloneConfiguration server = new RedisStandaloneConfiguration();
        server.setHostName(props.getHost());
        server.setPort(props.getPort());
        server.setDatabase(props.getDatabase());
        if (StringUtils.hasText(props.getPassword())) {
            server.setPassword(RedisPassword.of(props.getPassword()));
        }

        SocketOptions socketOptions = SocketOptions.builder()
                .connectTimeout(connectTimeout)
                .build();
        ClientOptions clientOptions = ClientOptions.builder()
                .socketOptions(socketOptions)
                // 说明：显式开启自动重连，Redis 重启后会自动恢复（期间请求仍可能因超时失败）。
                .autoReconnect(true)
                .build();

        LettuceClientConfiguration client = LettuceClientConfiguration.builder()
                .commandTimeout(commandTimeout)
                .clientOptions(clientOptions)
                .build();

        LettuceConnectionFactory factory = new LettuceConnectionFactory(server, client);
        factory.setValidateConnection(props.isValidateConnection());
        // 确保在设置给 SaTokenDao 前已完成初始化
        factory.afterPropertiesSet();
        return factory;
    }

    @Primary
    @Bean
    public SaTokenDao saTokenDao(LettuceConnectionFactory saTokenRedisConnectionFactory) {
        SaTokenDaoRedisJackson dao = new SaTokenDaoRedisJackson();
        dao.init(saTokenRedisConnectionFactory);
        return dao;
    }

    @Bean
    public Object saTokenDaoStaticInitializer(SaTokenDao saTokenDao) {
        SaManager.setSaTokenDao(saTokenDao);
        return new Object();
    }

    @Bean
    public ApplicationRunner saTokenRedisStartupCheck(
            SaTokenAloneRedisProperties props,
            LettuceConnectionFactory saTokenRedisConnectionFactory
    ) {
        return args -> {
            if (!props.isStartupCheckEnabled()) {
                return;
            }
            RedisConnection connection = null;
            try {
                connection = saTokenRedisConnectionFactory.getConnection();
                String pong = connection.ping();
                log.info("sa-token redis startup check ok: ping={}", pong);
            } catch (Exception e) {
                // 说明：只做告警不阻断启动，避免联调环境中 Redis 短暂不可用导致无法启动服务。
                log.warn("sa-token redis startup check failed: errType={}, err={}",
                        e.getClass().getName(), e.getMessage());
            } finally {
                if (connection != null) {
                    try {
                        connection.close();
                    } catch (Exception ignored) {
                        // ignore
                    }
                }
            }
        };
    }
}
