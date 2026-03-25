package com.bootcloud.common.feign.dto.base;

import java.io.Serial;
import java.io.Serializable;

/**
 * boot-cloud-base 内部租户管理请求 DTO。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一承载租户创建与更新所需字段，避免内部 Feign 接口继续直接透传 Map。</li>
 *   <li>siteRole 用于区分“主入口站点”与“业务站点”，便于后续默认租户切换。</li>
 * </ul>
 */
public class BaseTenantUpsertRequest implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 租户编码。
     */
    private String tenantCode;

    /**
     * 租户名称。
     */
    private String name;

    /**
     * 状态：1 启用，0 禁用。
     */
    private Integer status;

    /**
     * 站点定位。
     *
     * <p>当前约定值：</p>
     * <ul>
     *   <li>PRIMARY_PORTAL：主入口站点</li>
     *   <li>BUSINESS_SITE：业务站点</li>
     * </ul>
     */
    private String siteRole;

    /**
     * 备注。
     */
    private String remark;

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

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }
}
