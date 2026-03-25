package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 管理员用户实体，对应共享后台账号表 `t_admin_user`。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>本实体仅用于 boot-cloud-auth 的后台管理员认证（grant_type=admin_password）。</li>
 *   <li>字段只保留认证必需的最小集合，避免后台领域模型侵入认证中心。</li>
 * </ul>
 */
@Data
@TableName("t_admin_user")
public class AdminAuthUserEntity {

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("tenant_id")
    private Long tenantId;

    @TableField("scope_type")
    private String scopeType;

    @TableField("username")
    private String username;

    @TableField("password")
    private String password;

    @TableField("status")
    private Integer status;

    @TableField("deleted")
    private Integer deleted;

    /**
     * 角色状态（来自联表查询结果，非 t_admin_user 原生字段）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于登录阶段判定“角色是否启用”，避免账号启用但角色禁用仍可登录。</li>
     *   <li>该字段仅作为查询承载，不参与持久化写入。</li>
     * </ul>
     */
    @TableField(exist = false)
    private Integer roleStatus;
}
