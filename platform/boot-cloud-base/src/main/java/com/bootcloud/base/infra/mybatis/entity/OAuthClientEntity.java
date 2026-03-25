package com.bootcloud.base.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * OAuth2 client 管理表映射（boot-cloud-base 侧）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot-cloud-auth 会从该表读取 client 并校验 secret（支持 BCrypt）。</li>
 *   <li>boot-cloud-base 提供管理 API 负责写入/更新该表（尤其是 secret 的 hash 化）。</li>
 *   <li>当前支持 SYSTEM / TENANT 两种作用域，系统级 client 固定 tenantId=0。</li>
 * </ul>
 *
 * <p>表结构见：{@code doc/sql/boot-cloud-auth-mysql.sql}</p>
 */
@Data
@TableName("boot_cloud_oauth_client")
public class OAuthClientEntity {

    /**
     * OAuth client 作用域类型：SYSTEM=系统级，TENANT=租户级。
     */
    public static final String SCOPE_TYPE_SYSTEM = "SYSTEM";
    public static final String SCOPE_TYPE_TENANT = "TENANT";

    /**
     * 系统级 OAuth client 固定 tenant_id。
     */
    public static final long SYSTEM_TENANT_ID = 0L;

    @TableId(type = IdType.AUTO)
    private Long id;

    @TableField("tenant_id")
    private Long tenantId;

    /**
     * 作用域类型：SYSTEM=系统级，TENANT=租户级。
     */
    @TableField("scope_type")
    private String scopeType;

    @TableField("client_id")
    private String clientId;

    /**
     * client_secret（建议只存 BCrypt hash）。
     */
    @TableField("client_secret")
    private String clientSecret;

    @TableField("client_name")
    private String clientName;

    /**
     * grant_types（CSV）：authorization_code,password,client_credentials,refresh_token
     */
    @TableField("grant_types")
    private String grantTypes;

    /**
     * scopes（CSV）：read,write（或空字符串）
     */
    @TableField("scopes")
    private String scopes;

    /**
     * redirect_uri 列表：支持 CSV 或 JSON 数组字符串（两种都支持）。
     */
    @TableField("redirect_uris")
    private String redirectUris;

    @TableField("access_token_ttl_s")
    private Integer accessTokenTtlSeconds;

    @TableField("refresh_token_ttl_s")
    private Integer refreshTokenTtlSeconds;

    @TableField("allow_refresh_token")
    private Integer allowRefreshToken;

    /**
     * 状态：1 启用 0 禁用
     */
    @TableField("status")
    private Integer status;

    @TableField("remark")
    private String remark;

    @TableField("created_at")
    private LocalDateTime createdAt;

    @TableField("updated_at")
    private LocalDateTime updatedAt;
}
