package com.bootcloud.auth.infra.mybatis.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * OAuth2 client 数据表映射（多租户）。
 *
 * <p>表结构来源：{@code doc/sql/boot-cloud-auth-mysql.sql} 中的 {@code boot_cloud_oauth_client}。</p>
 *
 * <p>后续扩展说明：</p>
 * <ul>
 *   <li>可在 boot-cloud-base 提供 client 管理 API，boot-cloud-auth 只负责读取与校验。</li>
 *   <li>当前支持 SYSTEM / TENANT 双层作用域，系统级 client 固定 tenantId=0。</li>
 *   <li>可继续增加 client 的 IP 白名单、回调域名校验策略、PKCE 强制等字段。</li>
 * </ul>
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

    @TableField("client_secret")
    private String clientSecret;

    @TableField("client_name")
    private String clientName;

    /**
     * CSV: authorization_code,password,client_credentials,refresh_token
     */
    @TableField("grant_types")
    private String grantTypes;

    /**
     * CSV: read,write 或空字符串
     */
    @TableField("scopes")
    private String scopes;

    /**
     * redirect uri 列表：允许 CSV 或 JSON 数组字符串（两种都支持）
     */
    @TableField("redirect_uris")
    private String redirectUris;

    @TableField("access_token_ttl_s")
    private Integer accessTokenTtlSeconds;

    @TableField("refresh_token_ttl_s")
    private Integer refreshTokenTtlSeconds;

    @TableField("allow_refresh_token")
    private Integer allowRefreshToken;

    @TableField("status")
    private Integer status;
}
