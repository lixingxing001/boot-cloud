package com.bootcloud.auth.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.auth.infra.mybatis.entity.AdminAuthUserEntity;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

/**
 * 后台管理员认证查询 Mapper。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>保留 MyBatis-Plus 的基础 CRUD 能力。</li>
 *   <li>额外补一条“兼容旧数据的系统级超管查询”，避免只靠 scope_type/tenant_id 导致历史 admin 登录态被误判。</li>
 * </ul>
 */
@Mapper
public interface AdminAuthUserMapper extends BaseMapper<AdminAuthUserEntity> {

    /**
     * 按用户名查询“兼容旧数据”的系统级超级管理员候选。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>优先命中已经完成迁移的 SYSTEM/0 账号。</li>
     *   <li>同时兼容历史上仅绑定了 super_admin 角色、但用户 tenant_id/scope_type 还没完全收口的旧数据。</li>
     * </ul>
     */
    @Select("""
            SELECT u.id,
                   u.tenant_id,
                   u.scope_type,
                   u.username,
                   u.password,
                   u.status,
                   u.deleted,
                   r.status AS role_status
            FROM t_admin_user u
            INNER JOIN t_admin_role r ON u.role_id = r.id
            WHERE u.username = #{username}
              AND u.deleted = 0
              AND u.status = 1
              AND r.deleted = 0
              AND r.status = 1
              AND r.role_code = 'super_admin'
            ORDER BY CASE
                         WHEN u.scope_type = 'SYSTEM' AND COALESCE(u.tenant_id, 0) = 0 THEN 0
                         ELSE 1
                     END,
                     u.id ASC
            LIMIT 1
            """)
    AdminAuthUserEntity selectCompatibleSystemAdminByUsername(@Param("username") String username);

    /**
     * 按租户 + 用户名查询启用态的租户管理员候选（登录主链路）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>这里同时校验管理员账号状态与角色状态都为启用。</li>
     *   <li>避免出现“账号启用但角色禁用”仍可登录的漏洞。</li>
     * </ul>
     */
    @Select("""
            SELECT u.id,
                   u.tenant_id,
                   u.scope_type,
                   u.username,
                   u.password,
                   u.status,
                   u.deleted,
                   r.status AS role_status
            FROM t_admin_user u
            INNER JOIN t_admin_role r ON u.role_id = r.id
            WHERE u.username = #{username}
              AND u.tenant_id = #{tenantId}
              AND u.scope_type = 'TENANT'
              AND u.deleted = 0
              AND u.status = 1
              AND r.deleted = 0
              AND r.status = 1
            ORDER BY u.id ASC
            LIMIT 1
            """)
    AdminAuthUserEntity selectTenantAdminByTenantIdAndUsername(
            @Param("tenantId") Long tenantId,
            @Param("username") String username
    );

    /**
     * 按用户名查询“兼容旧数据”的系统级超管候选，包含禁用态（用于禁用提示判断）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>只过滤 deleted，保留 status 原值，便于区分“凭证错误”和“账号/角色禁用”。</li>
     * </ul>
     */
    @Select("""
            SELECT u.id,
                   u.tenant_id,
                   u.scope_type,
                   u.username,
                   u.password,
                   u.status,
                   u.deleted,
                   r.status AS role_status
            FROM t_admin_user u
            INNER JOIN t_admin_role r ON u.role_id = r.id
            WHERE u.username = #{username}
              AND u.deleted = 0
              AND r.deleted = 0
              AND r.role_code = 'super_admin'
            ORDER BY CASE
                         WHEN u.scope_type = 'SYSTEM' AND COALESCE(u.tenant_id, 0) = 0 THEN 0
                         ELSE 1
                     END,
                     u.id ASC
            LIMIT 1
            """)
    AdminAuthUserEntity selectCompatibleSystemAdminByUsernameIncludingDisabled(@Param("username") String username);

    /**
     * 按租户 + 用户名查询租户管理员候选，包含禁用态（用于禁用提示判断）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>只过滤 deleted，保留 status 原值，便于在密码命中后给出“账号禁用”提示。</li>
     * </ul>
     */
    @Select("""
            SELECT u.id,
                   u.tenant_id,
                   u.scope_type,
                   u.username,
                   u.password,
                   u.status,
                   u.deleted,
                   r.status AS role_status
            FROM t_admin_user u
            INNER JOIN t_admin_role r ON u.role_id = r.id
            WHERE u.username = #{username}
              AND u.tenant_id = #{tenantId}
              AND u.scope_type = 'TENANT'
              AND u.deleted = 0
              AND r.deleted = 0
            ORDER BY u.id ASC
            LIMIT 1
            """)
    AdminAuthUserEntity selectTenantAdminByTenantIdAndUsernameIncludingDisabled(
            @Param("tenantId") Long tenantId,
            @Param("username") String username
    );
}

