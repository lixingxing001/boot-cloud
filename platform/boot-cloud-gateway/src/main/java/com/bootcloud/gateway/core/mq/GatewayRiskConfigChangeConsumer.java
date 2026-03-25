package com.bootcloud.gateway.core.mq;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.gateway.core.risk.GatewayRiskDbConfigSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.ConsumeMode;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * GateShield 配置变更消息消费者。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>消费到变更消息后，网关立即回源 boot-cloud-base 拉取最新版本。</li>
 *   <li>消费逻辑按版本号去重，避免重复拉取。</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "boot.cloud.gateway.risk.db-sync",
        name = {"enabled", "mq-enabled"},
        havingValue = "true"
)
@RocketMQMessageListener(
        topic = "${boot.cloud.rocketmq.topic-gateway-risk-config:GATEWAY_RISK_CONFIG_CHANGED}",
        consumerGroup = "${boot.cloud.rocketmq.consumer-gateway-risk-config:boot-cloud-gateway-risk-config-consumer}",
        consumeMode = ConsumeMode.CONCURRENTLY
)
public class GatewayRiskConfigChangeConsumer implements RocketMQListener<String> {

    private static final String DEFAULT_CONFIG_CODE = "GATEWAY_RISK_SHIELD";

    private final ObjectMapper objectMapper;
    private final GatewayRiskDbConfigSyncService dbConfigSyncService;

    @Override
    public void onMessage(String message) {
        if (message == null || message.isBlank()) {
            log.warn("收到空的 GateShield 变更消息，已忽略");
            return;
        }
        try {
            JsonNode root = objectMapper.readTree(message);
            String configCode = root.path("configCode").asText("");
            long version = root.path("version").asLong(-1L);
            if (!DEFAULT_CONFIG_CODE.equalsIgnoreCase(configCode)) {
                if (log.isDebugEnabled()) {
                    log.debug("收到非 GateShield 消息，已忽略：configCode={}", configCode);
                }
                return;
            }
            log.info("收到 GateShield 配置变更消息：version={}", version);
            dbConfigSyncService.refreshFromDb("mq", version > 0 ? version : null);
        } catch (Exception e) {
            log.error("消费 GateShield 配置变更消息失败：message={}", message, e);
        }
    }
}
