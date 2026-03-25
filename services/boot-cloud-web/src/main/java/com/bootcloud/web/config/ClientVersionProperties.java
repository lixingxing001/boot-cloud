package com.bootcloud.web.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 客户端版本治理配置。
 *
 * <p>脚手架默认区分两类前端：</p>
 * <ul>
 *   <li>public: 面向普通用户入口</li>
 *   <li>admin: 面向管理后台</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.web.version-refresh")
public class ClientVersionProperties {

    /** 总开关。 */
    private boolean enabled = true;

    /** 需要强校验的路径白名单。 */
    private List<String> enforcePathPatterns = new ArrayList<>(List.of("/api/**"));

    /** 强校验排除路径。 */
    private List<String> enforceExcludePathPatterns = new ArrayList<>(List.of(
            "/api/web/runtime/version-meta",
            "/api/web/admin/runtime/version-meta",
            "/api/web/auth/**",
            "/api/web/admin/auth/**"
    ));

    /** 普通入口版本策略。 */
    private ClientVersionPolicy primary = new ClientVersionPolicy();

    /** 管理入口版本策略。 */
    private ClientVersionPolicy admin = new ClientVersionPolicy();

    @Data
    public static class ClientVersionPolicy {
        /** 当前推荐 buildId。 */
        private String currentBuildId = "dev-local";
        /** 刷新策略。 */
        private String refreshPolicy = "soft";
        /** 提示文案。 */
        private String message = "检测到新版本，请刷新页面后继续操作";
        /** 强制刷新倒计时，单位秒。 */
        private long graceSeconds = 45;
        /** 是否启用后端强校验。 */
        private boolean enforceOnMismatch = false;
        /** 允许通过强校验的 buildId 列表。 */
        private List<String> acceptedBuildIds = new ArrayList<>();
    }
}
