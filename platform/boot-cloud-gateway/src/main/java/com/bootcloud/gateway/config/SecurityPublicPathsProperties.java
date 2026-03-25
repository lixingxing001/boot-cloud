package com.bootcloud.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 公共白名单路径配置（从 boot-cloud-oauth-common.yaml 读取）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>无需登录可访问的接口只在一处配置。</li>
 *   <li>网关与资源服务各自都有安全规则，因此两边都需要读取同一份白名单。</li>
 *   <li>该配置位于公共 DataId：boot-cloud-oauth-common.yaml。</li>
 * </ul>
 *
 * <p>配置示例：</p>
 * <pre>
 * boot:
 *   cloud:
 *     security:
 *       public-paths:
 *         - /oauth/**
 *         - /api/auth/**
 *         - /api/admin/config
 * </pre>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.security")
public class SecurityPublicPathsProperties {

    /**
     * 无需鉴权的公共路径（Ant 风格）。
     */
    private List<String> publicPaths = new ArrayList<>();
}
