package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 用户二次验证配置（TOTP，与 业务服务 共用表）。
 */
@Data
@TableName("t_user_mfa_totp")
public class UserMfaTotpEntity {

    @TableId
    private Long id;

    @TableField("tenant_id")
    private Long tenantId;

    @TableField("user_id")
    private Long userId;

    @TableField("secret_base32")
    private String secretBase32;

    @TableField("enabled")
    private Integer enabled;

    @TableField("deleted")
    private Integer deleted;
}
