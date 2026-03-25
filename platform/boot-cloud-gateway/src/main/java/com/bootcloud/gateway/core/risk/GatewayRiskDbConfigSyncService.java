package com.bootcloud.gateway.core.risk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.core.internal.InternalHmacAuth;
import com.bootcloud.gateway.config.GatewayRiskSyncProperties;
import com.bootcloud.gateway.config.GatewayRiskShieldProperties;
import com.bootcloud.gateway.config.GatewayInternalAuthProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 网关 GateShield 配置同步服务（DB + MQ）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>收到 MQ 变更通知后，主动从 boot-cloud-base 拉取最新配置并热更新。</li>
 *   <li>保留低频兜底拉取，解决消息丢失和服务重启导致的版本漂移。</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GatewayRiskDbConfigSyncService {

    private static final String DEFAULT_CONFIG_CODE = "GATEWAY_RISK_SHIELD";

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final GatewayRiskSyncProperties dbSyncProperties;
    private final GatewayInternalAuthProperties internalAuthProperties;
    private final GatewayRiskShieldProperties riskProperties;

    private final AtomicLong loadedVersion = new AtomicLong(-1L);
    private final Object applyLock = new Object();

    @Value("${spring.application.name:boot-cloud-gateway}")
    private String serviceName;

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        if (!dbSyncProperties.isEnabled()) {
            log.info("GateShield DB 同步未启用，当前沿用 Nacos 配置");
            return;
        }
        if (dbSyncProperties.getSourceMode() == GatewayRiskSyncProperties.SourceMode.NACOS_ONLY) {
            log.info("GateShield 数据源模式为 NACOS_ONLY，跳过启动拉取");
            return;
        }
        refreshFromDb("startup", null);
    }

    @Scheduled(
            fixedDelayString = "${boot.cloud.gateway.risk.db-sync.fallback-pull-interval-ms:600000}",
            initialDelayString = "${boot.cloud.gateway.risk.db-sync.fallback-pull-initial-delay-ms:120000}"
    )
    public void scheduledFallbackPull() {
        if (!dbSyncProperties.isEnabled()
                || !dbSyncProperties.isFallbackPullEnabled()
                || dbSyncProperties.getSourceMode() == GatewayRiskSyncProperties.SourceMode.NACOS_ONLY) {
            return;
        }
        refreshFromDb("fallback", null);
    }

    public void refreshFromDb(String trigger, Long hintedVersion) {
        if (!dbSyncProperties.isEnabled()
                || dbSyncProperties.getSourceMode() == GatewayRiskSyncProperties.SourceMode.NACOS_ONLY) {
            return;
        }

        long localVersion = loadedVersion.get();
        if (hintedVersion != null && hintedVersion > 0 && hintedVersion <= localVersion) {
            if (log.isDebugEnabled()) {
                log.debug("跳过 GateShield DB 拉取：hintedVersion={}, localVersion={}, trigger={}",
                        hintedVersion, localVersion, trigger);
            }
            return;
        }

        String path = normalizePath(dbSyncProperties.getFetchPath());
        String url = "http://" + dbSyncProperties.getBaseServiceId() + path;
        long timeoutMs = Math.max(500L, dbSyncProperties.getFetchTimeoutMs());

        try {
            String raw = webClient.get()
                    .uri(URI.create(url))
                    .headers(h -> injectInternalHeaders(h, path, "GET"))
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofMillis(timeoutMs));

            if (!StringUtils.hasText(raw)) {
                log.warn("GateShield DB 拉取返回空响应：trigger={}, url={}", trigger, url);
                return;
            }

            JsonNode root = objectMapper.readTree(raw);
            if (!root.path("success").asBoolean(false)) {
                String errorCode = root.path("error").path("code").asText("unknown");
                String errorMessage = root.path("error").path("message").asText("unknown");
                log.warn("GateShield DB 拉取失败：trigger={}, code={}, message={}", trigger, errorCode, errorMessage);
                return;
            }

            JsonNode data = root.path("data");
            String configCode = data.path("configCode").asText(DEFAULT_CONFIG_CODE);
            if (!DEFAULT_CONFIG_CODE.equalsIgnoreCase(configCode)) {
                log.warn("GateShield DB 拉取返回未知配置编码，已忽略：configCode={}, trigger={}", configCode, trigger);
                return;
            }

            long remoteVersion = data.path("version").asLong(-1L);
            JsonNode payloadNode = data.path("payload");
            if (!payloadNode.isObject() || remoteVersion <= 0L) {
                log.warn("GateShield DB 拉取数据不完整：trigger={}, version={}, payloadType={}",
                        trigger, remoteVersion, payloadNode.getNodeType());
                return;
            }

            if (remoteVersion <= loadedVersion.get()) {
                if (log.isDebugEnabled()) {
                    log.debug("GateShield DB 版本未变化：remoteVersion={}, localVersion={}, trigger={}",
                            remoteVersion, loadedVersion.get(), trigger);
                }
                return;
            }

            GatewayRiskShieldProperties incoming = objectMapper.convertValue(
                    payloadNode,
                    GatewayRiskShieldProperties.class
            );
            normalizeIncoming(incoming);

            synchronized (applyLock) {
                long before = loadedVersion.get();
                if (remoteVersion <= before) {
                    return;
                }
                applyToRuntime(incoming);
                loadedVersion.set(remoteVersion);
            }

            log.info("GateShield DB 配置已生效：trigger={}, version={}, mode={}, enabled={}, adminPolicyEnabled={}, adminPathCount={}",
                    trigger,
                    remoteVersion,
                    riskProperties.getMode(),
                    riskProperties.isEnabled(),
                    riskProperties.getAdminPolicy() != null && riskProperties.getAdminPolicy().isEnabled(),
                    riskProperties.getAdminPathPatterns() == null ? 0 : riskProperties.getAdminPathPatterns().size());
        } catch (Exception e) {
            if (dbSyncProperties.getSourceMode() == GatewayRiskSyncProperties.SourceMode.DB_ONLY) {
                log.error("GateShield DB_ONLY 模式拉取失败：trigger={}, url={}", trigger, url, e);
            } else {
                log.warn("GateShield DB 拉取失败，继续沿用当前配置：trigger={}, url={}, err={}",
                        trigger, url, e.getMessage());
            }
        }
    }

    public long currentVersion() {
        return loadedVersion.get();
    }

    private void injectInternalHeaders(HttpHeaders headers, String path, String method) {
        if (headers == null) {
            return;
        }
        String secret = internalAuthProperties.getInternalServiceSecret();
        if (!StringUtils.hasText(secret)) {
            log.warn("GateShield DB 拉取未注入内部鉴权头：boot.cloud.internal-auth.internal-service-secret 为空");
            return;
        }

        // 兼容旧版静态密钥头。
        if (StringUtils.hasText(internalAuthProperties.getInternalServiceHeader())) {
            headers.set(internalAuthProperties.getInternalServiceHeader().trim(), secret.trim());
        }

        // 注入 HMAC 头，兼容 boot-cloud-base 的内部接口验签能力。
        String timestamp = InternalHmacAuth.nowTimestampSeconds();
        String signature = InternalHmacAuth.sign(secret.trim(), serviceName, timestamp, method, path);
        headers.set(InternalHmacAuth.HEADER_SERVICE_NAME, serviceName);
        headers.set(InternalHmacAuth.HEADER_INTERNAL_TIMESTAMP, timestamp);
        headers.set(InternalHmacAuth.HEADER_INTERNAL_SIGN, signature);
    }

    private void normalizeIncoming(GatewayRiskShieldProperties incoming) {
        if (incoming == null) {
            throw new IllegalArgumentException("GateShield payload 为空");
        }
        normalizeRootPolicy(incoming);
        if (incoming.getAdminPathPatterns() == null || incoming.getAdminPathPatterns().isEmpty()) {
            incoming.setAdminPathPatterns(new ArrayList<>(List.of("/api/admin/**", "/api/web/admin/**")));
        }
        if (incoming.getAdminPolicy() != null) {
            normalizePolicy(incoming.getAdminPolicy());
        }
    }

    private void normalizeRootPolicy(GatewayRiskShieldProperties policy) {
        if (policy == null) {
            return;
        }
        if (policy.getMode() == null) {
            policy.setMode(GatewayRiskShieldProperties.Mode.ENFORCE);
        }
        if (policy.getIgnorePaths() == null) {
            policy.setIgnorePaths(new ArrayList<>(List.of("/actuator/**")));
        }
        if (policy.getIp() == null) {
            policy.setIp(new GatewayRiskShieldProperties.IpRules());
        }
        if (policy.getGeo() == null) {
            policy.setGeo(new GatewayRiskShieldProperties.GeoRules());
        }
        normalizeIpGeo(policy.getIp(), policy.getGeo());
    }

    private void normalizePolicy(GatewayRiskShieldProperties.RiskPolicy policy) {
        if (policy == null) {
            return;
        }
        if (policy.getMode() == null) {
            policy.setMode(GatewayRiskShieldProperties.Mode.ENFORCE);
        }
        if (policy.getIgnorePaths() == null) {
            policy.setIgnorePaths(new ArrayList<>(List.of("/actuator/**")));
        }
        if (policy.getIp() == null) {
            policy.setIp(new GatewayRiskShieldProperties.IpRules());
        }
        if (policy.getGeo() == null) {
            policy.setGeo(new GatewayRiskShieldProperties.GeoRules());
        }
        normalizeIpGeo(policy.getIp(), policy.getGeo());
    }

    private void normalizeIpGeo(GatewayRiskShieldProperties.IpRules ip, GatewayRiskShieldProperties.GeoRules geo) {
        if (ip.getForwardedHeaderCandidates() == null) {
            ip.setForwardedHeaderCandidates(new ArrayList<>(List.of("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP")));
        }
        if (ip.getAllowList() == null) {
            ip.setAllowList(new ArrayList<>());
        }
        if (ip.getDenyList() == null) {
            ip.setDenyList(new ArrayList<>());
        }

        if (geo.getAllowCountries() == null) {
            geo.setAllowCountries(new ArrayList<>());
        }
        if (geo.getDenyCountries() == null) {
            geo.setDenyCountries(new ArrayList<>());
        }
        if (geo.getCidrCountryMap() == null) {
            geo.setCidrCountryMap(new LinkedHashMap<>());
        }
        if (geo.getUnknownCountryPolicy() == null) {
            geo.setUnknownCountryPolicy(GatewayRiskShieldProperties.UnknownCountryPolicy.ALLOW);
        }
        if (geo.getGeoIp() == null) {
            geo.setGeoIp(new GatewayRiskShieldProperties.GeoIp());
        }
    }

    private void applyToRuntime(GatewayRiskShieldProperties incoming) {
        applyRootPolicy(incoming, riskProperties);
        riskProperties.setAdminPathPatterns(incoming.getAdminPathPatterns());
        riskProperties.setAdminPolicy(incoming.getAdminPolicy());
    }

    private void applyRootPolicy(GatewayRiskShieldProperties from, GatewayRiskShieldProperties to) {
        if (from == null || to == null) {
            return;
        }
        to.setEnabled(from.isEnabled());
        to.setMode(from.getMode());
        to.setIncludePublicPaths(from.isIncludePublicPaths());
        to.setIgnorePaths(from.getIgnorePaths());
        to.setIp(from.getIp());
        to.setGeo(from.getGeo());
    }

    private String normalizePath(String rawPath) {
        String path = StringUtils.hasText(rawPath) ? rawPath.trim() : "/internal/admin/gateway-risk-config/current";
        return InternalHmacAuth.normalizePath(path);
    }
}
