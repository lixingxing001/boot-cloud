package com.bootcloud.base.core.gateshield;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.base.infra.mybatis.entity.GatewayRiskConfigEntity;
import com.bootcloud.base.infra.mybatis.mapper.GatewayRiskConfigMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 网关 GateShield 配置管理服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>负责 GateShield 配置的 DB 持久化。</li>
 *   <li>更新成功后在事务提交后发布 MQ 变更通知。</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GatewayRiskConfigService {

    public static final String DEFAULT_CONFIG_CODE = "GATEWAY_RISK_SHIELD";
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final GatewayRiskConfigMapper gatewayRiskConfigMapper;
    private final ObjectMapper objectMapper;
    private final GatewayRiskConfigChangePublisher changePublisher;

    public Snapshot getCurrent() {
        GatewayRiskConfigEntity entity = ensureConfigExists();
        return toSnapshot(entity);
    }

    @Transactional
    public Snapshot update(Map<String, Object> payload, String updatedBy, String remark) {
        validatePayload(payload);

        GatewayRiskConfigEntity entity = ensureConfigExists();
        long nextVersion = (entity.getVersion() == null ? 0L : entity.getVersion()) + 1L;

        entity.setConfigJson(writePayload(payload));
        entity.setVersion(nextVersion);
        entity.setStatus(1);
        entity.setUpdatedBy(StringUtils.hasText(updatedBy) ? updatedBy.trim() : "unknown");
        entity.setRemark(StringUtils.hasText(remark) ? remark.trim() : null);

        gatewayRiskConfigMapper.updateById(entity);
        Snapshot snapshot = toSnapshot(entity);

        // 事务提交后再发消息，避免“消息已发出但 DB 回滚”的不一致问题。
        afterCommit(() -> changePublisher.publishChanged(
                snapshot.configCode(),
                snapshot.version(),
                snapshot.updatedBy()
        ));

        log.info("GateShield 配置更新成功：configCode={}, version={}, updatedBy={}",
                snapshot.configCode(), snapshot.version(), snapshot.updatedBy());
        return snapshot;
    }

    private GatewayRiskConfigEntity ensureConfigExists() {
        GatewayRiskConfigEntity entity = findByCode(DEFAULT_CONFIG_CODE);
        if (entity != null) {
            return entity;
        }

        GatewayRiskConfigEntity init = new GatewayRiskConfigEntity();
        init.setConfigCode(DEFAULT_CONFIG_CODE);
        init.setConfigJson(writePayload(defaultPayload()));
        init.setVersion(1L);
        init.setStatus(1);
        init.setUpdatedBy("system");
        init.setRemark("初始化默认 GateShield 配置");
        try {
            gatewayRiskConfigMapper.insert(init);
            log.info("初始化 GateShield 配置成功：configCode={}, version={}", init.getConfigCode(), init.getVersion());
            return init;
        } catch (Exception e) {
            // 并发初始化时可能出现唯一键冲突，此时回查一次即可。
            GatewayRiskConfigEntity existed = findByCode(DEFAULT_CONFIG_CODE);
            if (existed != null) {
                return existed;
            }
            throw e;
        }
    }

    private GatewayRiskConfigEntity findByCode(String configCode) {
        return gatewayRiskConfigMapper.selectOne(new LambdaQueryWrapper<GatewayRiskConfigEntity>()
                .eq(GatewayRiskConfigEntity::getConfigCode, configCode)
                .last("LIMIT 1"));
    }

    private Snapshot toSnapshot(GatewayRiskConfigEntity entity) {
        Map<String, Object> payload = parsePayload(entity.getConfigJson());
        return new Snapshot(
                entity.getConfigCode(),
                entity.getVersion() == null ? 0L : entity.getVersion(),
                payload,
                entity.getUpdatedBy(),
                entity.getUpdatedAt() == null ? null : entity.getUpdatedAt().toString(),
                entity.getRemark()
        );
    }

    private Map<String, Object> parsePayload(String configJson) {
        if (!StringUtils.hasText(configJson)) {
            return defaultPayload();
        }
        try {
            return objectMapper.readValue(configJson, MAP_TYPE);
        } catch (Exception e) {
            log.warn("解析 GateShield 配置 JSON 失败，回退默认配置，err={}", e.getMessage());
            return defaultPayload();
        }
    }

    private String writePayload(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("GateShield 配置序列化失败: " + e.getMessage(), e);
        }
    }

    private void validatePayload(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            throw new IllegalArgumentException("payload 不能为空");
        }
        Object enabled = payload.get("enabled");
        if (enabled != null && !(enabled instanceof Boolean)) {
            throw new IllegalArgumentException("payload.enabled 必须是布尔值");
        }
    }

    /**
     * 默认配置与网关 Nacos 默认值保持同一语义，避免初始化阶段出现行为突变。
     */
    private Map<String, Object> defaultPayload() {
        Map<String, Object> out = defaultPolicyPayload();
        // 说明：补充管理端独立策略，默认与用户端策略一致，可在后台按场景单独调整。
        out.put("adminPathPatterns", new ArrayList<>(List.of("/api/admin/**", "/api/web/admin/**")));
        out.put("adminPolicy", defaultPolicyPayload());
        return out;
    }

    private Map<String, Object> defaultPolicyPayload() {
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("enabled", false);
        policy.put("mode", "ENFORCE");
        policy.put("includePublicPaths", true);
        policy.put("ignorePaths", new ArrayList<>(List.of("/actuator/**")));

        Map<String, Object> ip = new LinkedHashMap<>();
        ip.put("enabled", true);
        ip.put("trustForwardedHeaders", false);
        ip.put("forwardedHeaderCandidates", new ArrayList<>(List.of(
                "CF-Connecting-IP",
                "X-Forwarded-For",
                "X-Real-IP"
        )));
        ip.put("allowList", new ArrayList<>());
        ip.put("denyList", new ArrayList<>());
        policy.put("ip", ip);

        Map<String, Object> geo = new LinkedHashMap<>();
        geo.put("enabled", false);
        geo.put("trustCountryHeader", true);
        geo.put("countryHeaderName", "CF-IPCountry");
        geo.put("allowCountries", new ArrayList<>());
        geo.put("denyCountries", new ArrayList<>());
        geo.put("unknownCountryPolicy", "ALLOW");
        geo.put("cidrCountryMap", new LinkedHashMap<>());

        Map<String, Object> geoIp = new LinkedHashMap<>();
        geoIp.put("enabled", false);
        geoIp.put("mmdbPath", "");
        geo.put("geoIp", geoIp);

        policy.put("geo", geo);
        return policy;
    }

    private void afterCommit(Runnable runnable) {
        if (runnable == null) {
            return;
        }
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            runnable.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                runnable.run();
            }
        });
    }

    public record Snapshot(
            String configCode,
            long version,
            Map<String, Object> payload,
            String updatedBy,
            String updatedAt,
            String remark
    ) {
    }
}
