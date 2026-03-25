package com.bootcloud.web.core.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.common.feign.api.BaseTenantAdminApi;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 后台运行时租户服务。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>前端登录前需要知道“当前平台默认租户是谁”，这里统一从 boot-cloud-base 读取。</li>
 *   <li>这样切换默认租户后，管理端前端无需依赖重新发布环境变量。</li>
 * </ul>
 */
@Slf4j
@Service
public class AdminRuntimeTenantService {

    private final BaseTenantAdminApi baseTenantAdminApi;
    private final ObjectMapper objectMapper;

    public AdminRuntimeTenantService(BaseTenantAdminApi baseTenantAdminApi, ObjectMapper objectMapper) {
        this.baseTenantAdminApi = baseTenantAdminApi;
        this.objectMapper = objectMapper;
    }

    /**
     * 查询当前平台默认租户快照。
     */
    public DefaultTenantView getDefaultTenant() {
        try {
            String raw = baseTenantAdminApi.getDefaultTenantConfig();
            JsonNode root = objectMapper.readTree(raw);
            boolean success = root != null && root.path("success").asBoolean(false);
            if (!success) {
                String reason = extractReason(root);
                throw new IllegalStateException(StringUtils.hasText(reason) ? reason : "查询平台默认租户失败");
            }
            JsonNode data = root.path("data");
            DefaultTenantView view = objectMapper.treeToValue(data, DefaultTenantView.class);
            if (log.isDebugEnabled()) {
                log.debug("后台运行时默认租户加载完成: tenantId={}, tenantCode={}, source={}",
                        view.getTenantId(), view.getTenantCode(), view.getSource());
            }
            return view;
        } catch (Exception e) {
            log.error("后台运行时默认租户加载失败: msg={}", e.getMessage(), e);
            throw new IllegalStateException("加载后台默认租户失败", e);
        }
    }

    /**
     * 查询后台登录页可选租户列表。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>登录前只需要“可选站点快照”，返回最小字段避免暴露无关信息。</li>
     *   <li>当前默认仅返回启用租户（status=1），并保持与后台管理页一致的排序语义。</li>
     * </ul>
     */
    public List<LoginTenantView> listLoginTenants() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("status", 1);
        params.put("page", 1);
        params.put("size", 200);
        try {
            String raw = baseTenantAdminApi.pageTenants(params);
            JsonNode root = objectMapper.readTree(raw);
            boolean success = root != null && root.path("success").asBoolean(false);
            if (!success) {
                String reason = extractReason(root);
                throw new IllegalStateException(StringUtils.hasText(reason) ? reason : "查询登录租户列表失败");
            }

            JsonNode data = root.path("data");
            JsonNode records = data.path("records");
            List<LoginTenantView> out = new ArrayList<>();
            if (records.isArray()) {
                for (JsonNode item : records) {
                    LoginTenantView view = mapLoginTenant(item);
                    if (view.getId() > 0) {
                        out.add(view);
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("后台登录租户列表加载完成: count={}", out.size());
            }
            return out;
        } catch (Exception e) {
            log.error("后台登录租户列表加载失败: msg={}", e.getMessage(), e);
            throw new IllegalStateException("加载后台登录租户列表失败", e);
        }
    }

    /**
     * 根据租户 ID 查询登录站点，并校验其启用状态。
     *
     * <p>返回 null 表示租户不存在或未启用。</p>
     */
    public LoginTenantView getEnabledLoginTenantById(long tenantId) {
        if (tenantId <= 0) {
            return null;
        }
        try {
            String raw = baseTenantAdminApi.getTenant(tenantId);
            JsonNode root = objectMapper.readTree(raw);
            boolean success = root != null && root.path("success").asBoolean(false);
            if (!success) {
                String reason = extractReason(root);
                throw new IllegalStateException(StringUtils.hasText(reason) ? reason : "查询登录租户详情失败");
            }
            JsonNode data = root.path("data");
            LoginTenantView view = mapLoginTenant(data);
            if (view.getId() <= 0 || view.getStatus() == null || view.getStatus() != 1) {
                if (log.isWarnEnabled()) {
                    log.warn("登录租户详情不可用：tenantId={}, status={}", tenantId, view.getStatus());
                }
                return null;
            }
            return view;
        } catch (Exception e) {
            log.error("加载登录租户详情失败：tenantId={}, msg={}", tenantId, e.getMessage(), e);
            throw new IllegalStateException("加载登录租户详情失败", e);
        }
    }

    private static String extractReason(JsonNode root) {
        if (root == null || root.isNull()) {
            return null;
        }
        JsonNode error = root.path("error");
        if (error.isObject()) {
            String message = error.path("message").asText(null);
            if (StringUtils.hasText(message)) {
                return message;
            }
        }
        String message = root.path("message").asText(null);
        if (StringUtils.hasText(message)) {
            return message;
        }
        return null;
    }

    private static LoginTenantView mapLoginTenant(JsonNode item) {
        LoginTenantView view = new LoginTenantView();
        if (item == null || item.isNull()) {
            return view;
        }
        view.setId(item.path("id").asLong(0L));
        view.setTenantCode(item.path("tenantCode").asText(""));
        view.setName(item.path("name").asText(""));
        view.setStatus(item.path("status").asInt(0));
        view.setSiteRole(item.path("siteRole").asText(""));
        return view;
    }

    /**
     * 后台运行时默认租户快照。
     */
    public static class DefaultTenantView {

        /**
         * 当前默认租户 ID。
         */
        private Long tenantId;

        /**
         * 租户编码。
         */
        private String tenantCode;

        /**
         * 租户名称。
         */
        private String tenantName;

        /**
         * 站点定位。
         */
        private String siteRole;

        /**
         * 当前来源：DB 或 NACOS_FALLBACK。
         */
        private String source;

        public Long getTenantId() {
            return tenantId;
        }

        public void setTenantId(Long tenantId) {
            this.tenantId = tenantId;
        }

        public String getTenantCode() {
            return tenantCode;
        }

        public void setTenantCode(String tenantCode) {
            this.tenantCode = tenantCode;
        }

        public String getTenantName() {
            return tenantName;
        }

        public void setTenantName(String tenantName) {
            this.tenantName = tenantName;
        }

        public String getSiteRole() {
            return siteRole;
        }

        public void setSiteRole(String siteRole) {
            this.siteRole = siteRole;
        }

        public String getSource() {
            return source;
        }

        public void setSource(String source) {
            this.source = source;
        }
    }

    /**
     * 后台登录页租户选项。
     */
    public static class LoginTenantView {

        /**
         * 租户 ID。
         */
        private Long id;

        /**
         * 租户编码。
         */
        private String tenantCode;

        /**
         * 租户名称。
         */
        private String name;

        /**
         * 租户状态：1 启用，0 禁用。
         */
        private Integer status;

        /**
         * 站点定位：PRIMARY_PORTAL / BUSINESS_SITE。
         */
        private String siteRole;

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getTenantCode() {
            return tenantCode;
        }

        public void setTenantCode(String tenantCode) {
            this.tenantCode = tenantCode;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Integer getStatus() {
            return status;
        }

        public void setStatus(Integer status) {
            this.status = status;
        }

        public String getSiteRole() {
            return siteRole;
        }

        public void setSiteRole(String siteRole) {
            this.siteRole = siteRole;
        }
    }
}
