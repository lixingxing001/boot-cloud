package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 网关系统级 API 防护配置（GateShield）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>根级字段作为默认策略，主要面向用户端流量。</li>
 *   <li>管理端可通过 {@link #adminPolicy} 配置独立策略，避免误操作把后台锁死。</li>
 *   <li>管理端识别路径由 {@link #adminPathPatterns} 控制，支持 Ant 风格匹配。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.gateway.risk")
public class GatewayRiskShieldProperties {

    /**
     * 总开关。
     *
     * <p>false: 关闭 GateShield，所有子规则不生效。</p>
     * <p>true: 启用 GateShield，具体行为由 {@link #mode} 决定。</p>
     */
    private boolean enabled = false;

    /**
     * 执行模式。
     *
     * <p>ENFORCE：命中规则后直接拦截，返回 403。</p>
     * <p>DRY_RUN：命中规则后仅审计日志，继续放行请求。</p>
     */
    private Mode mode = Mode.ENFORCE;

    /**
     * 是否对网关 public paths 也执行风控。
     *
     * <p>默认 true：公开接口同样可能遭受刷接口/撞库等攻击。</p>
     */
    private boolean includePublicPaths = true;

    /**
     * 风控忽略路径（Ant 风格）。
     *
     * <p>用于健康检查或临时应急放行。</p>
     */
    private List<String> ignorePaths = new ArrayList<>(List.of("/actuator/**"));

    private IpRules ip = new IpRules();

    private GeoRules geo = new GeoRules();

    /**
     * 管理端路径匹配规则（Ant 风格）。
     *
     * <p>命中后优先使用 {@link #adminPolicy}（若已配置）。</p>
     */
    private List<String> adminPathPatterns = new ArrayList<>(List.of(
            "/api/admin/**",
            "/api/web/admin/**"
    ));

    /**
     * 管理端独立策略。
     *
     * <p>为空时沿用根级默认策略（用户端策略）。</p>
     */
    private RiskPolicy adminPolicy;

    /**
     * 场景策略定义。
     *
     * <p>用于表达与根级字段同构的一套完整规则，当前用于 adminPolicy。</p>
     */
    @Data
    public static class RiskPolicy {

        private boolean enabled = false;

        private Mode mode = Mode.ENFORCE;

        private boolean includePublicPaths = true;

        private List<String> ignorePaths = new ArrayList<>(List.of("/actuator/**"));

        private IpRules ip = new IpRules();

        private GeoRules geo = new GeoRules();
    }

    @Data
    public static class IpRules {

        /**
         * IP 规则开关。
         *
         * <p>false 时，IP 白名单/黑名单均不参与判定。</p>
         */
        private boolean enabled = true;

        /**
         * 是否信任转发头中的客户端 IP。
         *
         * <p>默认 false，防止外部伪造转发头。</p>
         */
        private boolean trustForwardedHeaders = false;

        /**
         * 客户端 IP 候选头（按优先级）。
         *
         * <p>仅在 {@link #trustForwardedHeaders} 为 true 时启用。</p>
         * <p>例如 X-Forwarded-For 场景仅取第一个 IP。</p>
         */
        private List<String> forwardedHeaderCandidates = new ArrayList<>(List.of(
                "CF-Connecting-IP",
                "X-Forwarded-For",
                "X-Real-IP"
        ));

        /**
         * IP 白名单（支持单 IP 或 CIDR）。
         *
         * <p>当非空时，只有命中白名单的 IP 才可访问。</p>
         */
        private List<String> allowList = new ArrayList<>();

        /**
         * IP 黑名单（支持单 IP 或 CIDR）。
         *
         * <p>当白名单为空时，命中黑名单即拦截。</p>
         */
        private List<String> denyList = new ArrayList<>();
    }

    @Data
    public static class GeoRules {

        /**
         * 地区规则开关。
         *
         * <p>false 时，地区白名单/黑名单均不参与判定。</p>
         */
        private boolean enabled = false;

        /**
         * 是否信任上游透传国家码头。
         *
         * <p>如 Cloudflare 的 {@code CF-IPCountry}。</p>
         */
        private boolean trustCountryHeader = true;

        /**
         * 国家码头名称。
         *
         * <p>国家码格式为 ISO 3166-1 alpha-2，例如 US、SG。</p>
         */
        private String countryHeaderName = "CF-IPCountry";

        /**
         * 国家白名单（ISO 3166-1 alpha-2）。
         *
         * <p>当非空时，仅放行该集合。</p>
         */
        private List<String> allowCountries = new ArrayList<>();

        /**
         * 国家黑名单（ISO 3166-1 alpha-2）。
         *
         * <p>当地区白名单为空时，命中黑名单即拦截。</p>
         */
        private List<String> denyCountries = new ArrayList<>();

        /**
         * 未命中国家码时的策略。
         */
        private UnknownCountryPolicy unknownCountryPolicy = UnknownCountryPolicy.ALLOW;

        /**
         * 基于 CIDR 的国家映射（可选）。
         *
         * <p>说明：当没有上游国家码头时，可先用小范围网段映射做补充，后续可替换为专业 Geo 库。</p>
         * <p>示例：{"SG": ["1.2.3.0/24"], "US": ["8.8.8.8/32"]}</p>
         */
        private Map<String, List<String>> cidrCountryMap = new LinkedHashMap<>();

        /**
         * GeoIP 本地库配置。
         *
         * <p>说明：用于根据客户端 IP 自动解析国家码，避免只依赖请求头。</p>
         */
        private GeoIp geoIp = new GeoIp();
    }

    @Data
    public static class GeoIp {

        /**
         * GeoIP 自动识别开关。
         *
         * <p>false 时，跳过 mmdb 查询。</p>
         * <p>true 时，在国家头缺失或不可信时尝试通过本地库识别。</p>
         */
        private boolean enabled = false;

        /**
         * mmdb 文件路径。
         *
         * <p>示例：/data/geo/GeoLite2-Country.mmdb。</p>
         * <p>支持绝对路径，建议挂载到网关容器只读目录。</p>
         */
        private String mmdbPath = "";
    }

    public enum Mode {
        /**
         * 强拦截模式，命中规则后返回 403。
         */
        ENFORCE,
        /**
         * 观察模式，命中规则仅记录日志。
         */
        DRY_RUN
    }

    public enum UnknownCountryPolicy {
        ALLOW,
        BLOCK
    }
}
