package com.bootcloud.gateway.core.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Nacos 配置热更新监听器（网关专用）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>你希望 Nacos 中的配置变更后，网关无需重启即可生效。</li>
 *   <li>Spring Cloud Gateway 的 routes 变更需要触发 RefreshRoutesEvent 才会立即生效。</li>
 *   <li>此监听器在检测到 gateway 相关配置变更时，主动发布刷新事件。</li>
 * </ul>
 */
@Component
public class NacosGatewayRefreshListener {

    private static final Logger log = LoggerFactory.getLogger(NacosGatewayRefreshListener.class);

    private final ApplicationEventPublisher publisher;

    public NacosGatewayRefreshListener(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @EventListener(EnvironmentChangeEvent.class)
    public void onEnvironmentChange(EnvironmentChangeEvent event) {
        Set<String> keys = event.getKeys();
        if (keys == null || keys.isEmpty()) {
            return;
        }

        boolean affectsGateway = keys.stream().anyMatch(k ->
                k != null && (k.startsWith("spring.cloud.gateway.") || k.startsWith("boot.cloud.gateway."))
        );

        if (!affectsGateway) {
            return;
        }

        log.info("检测到 Nacos 配置变更，触发网关路由刷新，keys={}", keys);
        publisher.publishEvent(new RefreshRoutesEvent(this));
    }
}

