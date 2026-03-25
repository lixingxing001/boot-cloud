package com.bootcloud.web.core.util;

import com.bootcloud.web.config.UserAuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 用户端“手动选择租户站点”Cookie 服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>测试环境无域名时，前端可以选择租户站点并写入 HttpOnly Cookie。</li>
 *   <li>后端读取该 Cookie 后可优先确定租户口径，避免刷新后回落默认租户。</li>
 * </ul>
 */
@Slf4j
@Component
public class UserTenantSelectionCookieService {

    private final UserAuthProperties.TenantSiteSelector props;

    public UserTenantSelectionCookieService(UserAuthProperties userAuthProperties) {
        this.props = userAuthProperties == null
                ? new UserAuthProperties.TenantSiteSelector()
                : userAuthProperties.getTenantSiteSelector();
    }

    /**
     * 是否启用“手动租户选择”能力。
     */
    public boolean isEnabled() {
        return props != null && props.isEnabled() && StringUtils.hasText(props.getCookieName());
    }

    /**
     * 读取当前请求中的手动选择租户。
     */
    public Long resolveSelectedTenantId(HttpServletRequest request) {
        if (!isEnabled()) {
            return null;
        }
        String cookieName = safeCookieName();
        String raw = DeviceIdCookieUtil.readCookie(request, cookieName);
        Long tenantId = normalizePositive(raw);
        if (tenantId != null && log.isDebugEnabled()) {
            log.debug("命中用户端手动租户 Cookie：cookieName={}, tenantId={}", cookieName, tenantId);
        }
        return tenantId;
    }

    /**
     * 写入用户端手动租户 Cookie。
     */
    public void writeSelectedTenantId(HttpServletResponse response, long tenantId) {
        if (!isEnabled() || response == null || tenantId <= 0) {
            return;
        }
        String cookieName = safeCookieName();
        DeviceIdCookieUtil.writeCookieWithSameSite(
                response,
                cookieName,
                String.valueOf(tenantId),
                Math.max(props.getCookieMaxAgeSeconds(), 1L),
                props.getCookiePath(),
                props.getCookieSameSite(),
                props.isCookieSecure(),
                props.getCookieDomain()
        );
        if (log.isInfoEnabled()) {
            log.info("用户端手动租户 Cookie 已写入：cookieName={}, tenantId={}", cookieName, tenantId);
        }
    }

    /**
     * 清理用户端手动租户 Cookie。
     */
    public void clearSelectedTenant(HttpServletResponse response) {
        if (!isEnabled() || response == null) {
            return;
        }
        String cookieName = safeCookieName();
        DeviceIdCookieUtil.clearCookie(response, cookieName, props.getCookiePath(), props.getCookieDomain());
        if (log.isDebugEnabled()) {
            log.debug("用户端手动租户 Cookie 已清理：cookieName={}", cookieName);
        }
    }

    private String safeCookieName() {
        String configured = props == null ? null : props.getCookieName();
        return StringUtils.hasText(configured) ? configured.trim() : "BOOT_CLOUD_USER_SELECTED_TENANT";
    }

    private static Long normalizePositive(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        try {
            long value = Long.parseLong(raw.trim());
            return value > 0 ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
