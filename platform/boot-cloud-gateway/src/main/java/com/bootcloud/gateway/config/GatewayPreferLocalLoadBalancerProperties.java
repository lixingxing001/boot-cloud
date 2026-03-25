package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * boot-cloud-gateway 本机优先负载均衡配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>场景：同一个服务名在 Nacos 中同时存在“本机实例”和“同事实例”。</li>
 *   <li>目标：当本机实例存在且健康时，网关优先路由到本机实例，方便你本地联调。</li>
 *   <li>回退：本机实例不可用时自动回退到其他实例。</li>
 * </ul>
 *
 * <p>注意：</p>
 * <ul>
 *   <li>只影响网关作为调用方的负载均衡选择（包括 Gateway 路由与 loadBalanced WebClient）。</li>
 *   <li>默认关闭，建议只在开发联调环境开启。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.gateway.lb.prefer-local")
public class GatewayPreferLocalLoadBalancerProperties {

    /**
     * 是否启用“本机实例优先”策略。
     */
    private boolean enabled = false;

    /**
     * 是否自动探测本机网卡 IP（IPv4）。
     *
     * <p>通常本机在 Nacos 注册的 ip 为 192.168.x.x 这类局域网地址，开启自动探测可以做到免配置。</p>
     */
    private boolean detectLocalIps = true;

    /**
     * 是否优先按“调用方 IP”选择实例。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>场景：网关部署在 192.168.3.80，你本机在 192.168.3.44 启了 boot-cloud-web。</li>
     *   <li>你从 192.168.3.44 访问网关时，希望网关优先路由到 192.168.3.44 的实例。</li>
     * </ul>
     *
     * <p>说明：</p>
     * <ul>
     *   <li>调用方 IP 由网关在请求入口计算，并写入内部 header（caller-ip-header-name）。</li>
     *   <li>如果没有匹配实例，会自动回退到“本机优先”或默认轮询。</li>
     * </ul>
     */
    private boolean preferCallerIp = true;

    /**
     * 网关写入的“调用方 IP”内部 header 名称。
     */
    private String callerIpHeaderName = "X-BootCloud-Caller-Ip";

    /**
     * 是否信任 X-Forwarded-For / X-Real-IP 等转发头。
     *
     * <p>默认 false：避免客户端伪造转发头影响路由。</p>
     */
    private boolean trustForwardedHeaders = false;

    /**
     * 手工补充本机 IP 列表（当自动探测不准确时使用）。
     *
     * <p>示例：["192.168.0.10"]</p>
     */
    private List<String> localIps = new ArrayList<>();
}
