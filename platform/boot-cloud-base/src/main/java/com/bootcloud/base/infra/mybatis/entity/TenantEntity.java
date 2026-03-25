package com.bootcloud.base.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 租户表实体（evm_tenant）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该表用于承载多租户基础信息（tenant_code/name/status）。</li>
 *   <li>tenant_code 可用于兼容历史系统的 siteCode（你提到的“多站点”概念）。</li>
 * </ul>
 */
@Data
@TableName("evm_tenant")
public class TenantEntity {

    @TableId(type = IdType.AUTO)
    private Long id;

    @TableField("tenant_code")
    private String tenantCode;

    @TableField("name")
    private String name;

    @TableField("status")
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
    @TableField("site_role")
    private String siteRole;

    @TableField("remark")
    private String remark;

    @TableField("created_at")
    private LocalDateTime createdAt;

    @TableField("updated_at")
    private LocalDateTime updatedAt;
}

