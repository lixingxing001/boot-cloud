package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 用户二次验证备份码（与 业务服务 共用表）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot-cloud-auth 需要在 password grant 时校验备份码，用于登录恢复。</li>
 *   <li>服务端只存哈希，不存明文。</li>
 * </ul>
 */
@Data
@TableName("t_user_mfa_backup_code")
public class UserMfaBackupCodeEntity {

    @TableId
    private Long id;

    @TableField("tenant_id")
    private Long tenantId;

    @TableField("user_id")
    private Long userId;

    @TableField("code_hash")
    private String codeHash;

    @TableField("code_suffix")
    private String codeSuffix;

    @TableField("used")
    private Integer used;

    @TableField("used_at")
    private LocalDateTime usedAt;

    @TableField("deleted")
    private Integer deleted;
}
