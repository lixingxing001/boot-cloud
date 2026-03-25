package com.bootcloud.web.core.version;

import com.bootcloud.common.core.error.AppException;
import com.bootcloud.common.core.error.CommonErrorCode;
import com.bootcloud.web.config.ClientVersionProperties;
import com.bootcloud.web.core.util.LogSafeUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 客户端版本拦截器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当策略开启 enforceOnMismatch 时，对关键接口执行 buildId 强校验。</li>
 *   <li>拦截失败统一返回 client_version_too_old，前端可直接触发刷新流程。</li>
 * </ul>
 */
@Slf4j
@Component
public class VersionRefreshInterceptor implements HandlerInterceptor {

    public static final String HEADER_CLIENT_APP = "X-Client-App";
    public static final String HEADER_CLIENT_BUILD_ID = "X-Client-Build-Id";

    private final VersionRefreshService versionRefreshService;
    private final ClientVersionProperties properties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public VersionRefreshInterceptor(
            VersionRefreshService versionRefreshService,
            ClientVersionProperties properties
    ) {
        this.versionRefreshService = versionRefreshService;
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!properties.isEnabled()) {
            return true;
        }
        String path = request.getRequestURI();
        if (!shouldCheckPath(path)) {
            return true;
        }
        String app = versionRefreshService.resolveAppByPathOrHeader(path, request.getHeader(HEADER_CLIENT_APP));
        if (!versionRefreshService.shouldEnforceVersion(app)) {
            return true;
        }
        String clientBuildId = request.getHeader(HEADER_CLIENT_BUILD_ID);
        if (versionRefreshService.isBuildAllowed(app, clientBuildId)) {
            return true;
        }

        VersionRefreshService.VersionPolicySnapshot snapshot = versionRefreshService.snapshot(app);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("app", app);
        details.put("path", path);
        details.put("clientBuildId", StringUtils.hasText(clientBuildId) ? clientBuildId.trim() : "");
        details.put("serverBuildId", snapshot.currentBuildId());
        details.put("refreshPolicy", snapshot.refreshPolicy());
        details.put("graceSeconds", snapshot.graceSeconds());

        log.warn("客户端版本过旧，已拦截请求：app={}, path={}, clientBuildId={}, serverBuildId={}, acceptedBuildIds={}",
                app,
                path,
                LogSafeUtil.sanitizeAndTruncate(clientBuildId, 96),
                snapshot.currentBuildId(),
                snapshot.acceptedBuildIds());

        throw new AppException(CommonErrorCode.CLIENT_VERSION_TOO_OLD, snapshot.message(), details);
    }

    private boolean shouldCheckPath(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        if (matches(path, properties.getEnforceExcludePathPatterns())) {
            return false;
        }
        return matches(path, properties.getEnforcePathPatterns());
    }

    private boolean matches(String path, List<String> patterns) {
        if (patterns == null || patterns.isEmpty()) {
            return false;
        }
        for (String pattern : patterns) {
            if (!StringUtils.hasText(pattern)) {
                continue;
            }
            if (pathMatcher.match(pattern.trim(), path)) {
                return true;
            }
        }
        return false;
    }
}
