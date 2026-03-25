package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * boot-cloud-gateway CORS 配置（开发环境联调用）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>浏览器从一个端口访问另一个端口（如 63342 -> 9000）会触发 CORS 预检（OPTIONS）。</li>
 *   <li>如果网关未返回 Access-Control-Allow-Origin 等响应头，浏览器会直接拦截请求并报 “Failed to fetch / CORS”。</li>
 *   <li>因此这里提供“可开关”的 CORS 过滤器：仅建议在开发/联调环境开启。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.gateway.cors")
public class GatewayCorsProperties {

    /**
     * 是否启用 CORS（建议仅在 dev 开启）。
     */
    private boolean enabled = false;

    /**
     * 允许的 Origin（使用 pattern，便于支持 localhost 任意端口）。
     *
     * <p>默认仅允许本机：{@code http://localhost:*}</p>
     */
    private List<String> allowedOriginPatterns = new ArrayList<>(List.of("http://localhost:*"));

    /**
     * 是否允许携带 Cookie/认证信息（本项目多数请求走 Bearer/satoken header，这里允许更通用）。
     */
    private boolean allowCredentials = true;

    /**
     * 允许的方法（默认允许常见方法，包含 OPTIONS 以通过预检）。
     */
    private List<String> allowedMethods = new ArrayList<>(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

    /**
     * 允许的请求头（开发阶段建议放开；生产可收敛到 Authorization、Content-Type、X-Tenant-Id、satoken 等）。
     */
    private List<String> allowedHeaders = new ArrayList<>(List.of("*"));

    /**
     * 允许暴露给前端读取的响应头（例如 token header）。
     */
    private List<String> exposedHeaders = new ArrayList<>(List.of("Authorization", "satoken"));

    /**
     * 预检缓存时间（秒）。
     */
    private long maxAgeSeconds = 1800;
}

