package com.bootcloud.base.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 网关风控配置实体（evm_gateway_risk_config）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于持久化 GateShield 配置快照，承载 IP/地区限制等规则。</li>
 *   <li>当前按 config_code 维度唯一存储，默认使用 GATEWAY_RISK_SHIELD。</li>
 * </ul>
 */
@Data
@TableName("evm_gateway_risk_config")
public class GatewayRiskConfigEntity {

    /**
     * 主键 ID。
     */
    @TableId(type = IdType.AUTO)
    private Long id;

    /**
     * 配置编码。
     */
    @TableField("config_code")
    private String configCode;

    /**
     * 配置 JSON 文本。
     */
    @TableField("config_json")
    private String configJson;

    /**
     * 配置版本号（每次更新递增）。
     */
    @TableField("version")
    private Long version;

    /**
     * 配置状态。
     */
    @TableField("status")
    private Integer status;

    /**
     * 最后更新人（后台管理员 ID 或账号）。
     */
    @TableField("updated_by")
    private String updatedBy;

    /**
     * 备注。
     */
    @TableField("remark")
    private String remark;

    /**
     * 创建时间。
     */
    @TableField("created_at")
    private LocalDateTime createdAt;

    /**
     * 更新时间。
     */
    @TableField("updated_at")
    private LocalDateTime updatedAt;
}
