package com.bootcloud.base.core.gateshield;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 网关风控配置变更消息发布器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当后台更新 GateShield 配置后，boot-cloud-base 通过 MQ 通知网关尽快拉取最新版本。</li>
 *   <li>消息发送失败不会回滚 DB 写入，网关仍可通过兜底拉取策略自愈。</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GatewayRiskConfigChangePublisher {

    private final ObjectProvider<RocketMQTemplate> rocketMQTemplateProvider;
    private final ObjectMapper objectMapper;

    @Value("${boot.cloud.rocketmq.topic-gateway-risk-config:GATEWAY_RISK_CONFIG_CHANGED}")
    private String topic;

    public void publishChanged(String configCode, long version, String updatedBy) {
        RocketMQTemplate rocketMQTemplate = rocketMQTemplateProvider.getIfAvailable();
        if (rocketMQTemplate == null) {
            log.warn("网关风控配置变更消息未发送：RocketMQTemplate 不可用，configCode={}, version={}", configCode, version);
            return;
        }

        if (!StringUtils.hasText(topic)) {
            log.warn("网关风控配置变更消息未发送：topic 为空，configCode={}, version={}", configCode, version);
            return;
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("eventType", "GATEWAY_RISK_CONFIG_CHANGED");
        payload.put("configCode", configCode);
        payload.put("version", version);
        payload.put("updatedBy", updatedBy);
        payload.put("publishedAt", LocalDateTime.now().toString());

        try {
            String message = objectMapper.writeValueAsString(payload);
            rocketMQTemplate.convertAndSend(topic, message);
            log.info("网关风控配置变更消息已发送：topic={}, configCode={}, version={}", topic, configCode, version);
        } catch (Exception e) {
            log.error("网关风控配置变更消息发送失败：topic={}, configCode={}, version={}", topic, configCode, version, e);
        }
    }
}
