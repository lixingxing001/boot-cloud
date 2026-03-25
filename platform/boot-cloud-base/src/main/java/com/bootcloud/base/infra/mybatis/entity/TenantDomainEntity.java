package com.bootcloud.base.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 域名 -> 租户 映射表实体。
 *
 * <p>表结构来源：{@code server/boot-cloud/doc/sql/boot-cloud-auth-mysql.sql} 中的 {@code evm_tenant_domain}。</p>
 *
 * <p>注意：</p>
 * <ul>
 *   <li>domain 建议存标准化 host（小写，不含协议/路径/端口）。</li>
 *   <li>当前阶段可先把 localhost 映射到 tenantId=1；后续多租户上线后逐步补全。</li>
 * </ul>
 */
@Data
@TableName("evm_tenant_domain")
public class TenantDomainEntity {

    @TableId(type = IdType.AUTO)
    private Long id;

    @TableField("tenant_id")
    private Long tenantId;

    @TableField("domain")
    private String domain;

    @TableField("is_primary")
    private Integer isPrimary;

    @TableField("status")
    private Integer status;

    @TableField("remark")
    private String remark;

    @TableField("created_at")
    private LocalDateTime createdAt;

    @TableField("updated_at")
    private LocalDateTime updatedAt;
}

