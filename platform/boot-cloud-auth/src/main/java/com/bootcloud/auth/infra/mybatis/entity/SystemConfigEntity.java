package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 系统配置表实体（t_system_config）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当前主要用于读取后台维护的默认租户配置。</li>
 *   <li>boot-cloud-auth 只读这张表，不在这里改写配置。</li>
 * </ul>
 */
@Data
@TableName("t_system_config")
public class SystemConfigEntity {

    @TableId(type = IdType.AUTO)
    private Long id;

    /**
     * 配置键。
     */
    @TableField("config_key")
    private String configKey;

    /**
     * 配置值。
     */
    @TableField("config_value")
    private String configValue;

    /**
     * 配置描述。
     */
    @TableField("description")
    private String description;

    @TableField("created_at")
    private LocalDateTime createdAt;

    @TableField("updated_at")
    private LocalDateTime updatedAt;
}
