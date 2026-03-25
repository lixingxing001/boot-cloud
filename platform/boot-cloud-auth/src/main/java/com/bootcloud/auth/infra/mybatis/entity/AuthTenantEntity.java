package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 认证中心视角的租户实体（evm_tenant）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当前仅用于校验租户是否启用。</li>
 *   <li>后续如果需要按站点角色做差异化策略，可在此基础上扩展字段。</li>
 * </ul>
 */
@Data
@TableName("evm_tenant")
public class AuthTenantEntity {

    /**
     * 租户主键 ID。
     */
    @TableId(type = IdType.AUTO)
    private Long id;

    /**
     * 状态：1 启用，0 禁用。
     */
    @TableField("status")
    private Integer status;
}
