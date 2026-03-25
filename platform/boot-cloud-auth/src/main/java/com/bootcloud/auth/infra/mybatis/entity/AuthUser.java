package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableLogic;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * OAuth2 password grant 用到的最小用户实体映射（复用 业务服务 的 {@code t_user} 表）。
 *
 * <p>为什么不直接依赖 业务服务 的实体：</p>
 * <ul>
 *   <li>避免在重构阶段把 auth 强耦合到业务服务的代码结构（目录迁移/分包会频繁变化）。</li>
 *   <li>这里只需要最小字段：{@code id/username/email/password/deleted}。</li>
 * </ul>
 *
 * <p>后续多租户演进：</p>
 * <ul>
 *   <li>当 {@code t_user} 增加 {@code tenant_id} 后，应在本实体中补充字段，并在查询条件中强制 tenant 过滤。</li>
 * </ul>
 */
@Data
@TableName("t_user")
public class AuthUser {

    @TableId(type = IdType.AUTO)
    private Long id;

    /**
     * 用户所属租户 ID。
     */
    @TableField("tenant_id")
    private Long tenantId;

    private String username;

    private String email;

    @TableField("password")
    private String password;

    @TableLogic
    private Integer deleted;
}

