package com.bootcloud.common.nacos.lb;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * 本机优先负载均衡配置项。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>推荐把该配置放到公共 DataId（例如 boot-cloud-oauth-common.yaml）中，便于全服务统一开启。</li>
 *   <li>当某些环境无法准确探测本机 IP 时，可手工配置 local-ips。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.lb.prefer-local")
public class PreferLocalLoadBalancerProperties {

    /**
     * 是否启用本机优先负载均衡。
     */
    private boolean enabled = false;

    /**
     * 是否自动探测本机 IP（默认 true）。
     */
    private boolean detectLocalIps = true;

    /**
     * 手工指定的本机 IP 列表。
     *
     * <p>说明：当运行在 WSL、容器、或多网卡环境探测不准时，用这个兜底。</p>
     */
    private List<String> localIps = new ArrayList<>();

    /**
     * 兼容场景：是否优先按“调用方 IP”选实例。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该能力更适合网关一类入口服务。</li>
     *   <li>普通服务内部调用一般没有 caller-ip 概念，因此默认 false。</li>
     * </ul>
     */
    private boolean preferCallerIp = false;

    /**
     * 调用方 IP header 名（当 prefer-caller-ip=true 时生效）。
     */
    private String callerIpHeaderName = "X-BootCloud-Caller-Ip";

    /**
     * 是否信任 forwarded headers（X-Forwarded-For / X-Real-IP）。
     *
     * <p>说明：默认 false，避免被外部伪造。</p>
     */
    private boolean trustForwardedHeaders = false;

    /**
     * 排除的应用名列表。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>典型用途：boot-cloud-gateway 有自己的增强版策略，因此默认可把 boot-cloud-gateway 放入排除列表，避免重复生效。</li>
     * </ul>
     */
    private List<String> excludeApplications = new ArrayList<>(List.of("boot-cloud-gateway"));

    public boolean isExcludedApplication(String appName) {
        if (!StringUtils.hasText(appName)) {
            return false;
        }
        if (excludeApplications == null || excludeApplications.isEmpty()) {
            return false;
        }
        for (String s : excludeApplications) {
            if (!StringUtils.hasText(s)) {
                continue;
            }
            if (appName.trim().equalsIgnoreCase(s.trim())) {
                return true;
            }
        }
        return false;
    }
}
