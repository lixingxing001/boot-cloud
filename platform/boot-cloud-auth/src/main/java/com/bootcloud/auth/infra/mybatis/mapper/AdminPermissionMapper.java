package com.bootcloud.auth.infra.mybatis.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * 管理员权限查询 Mapper。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>后台管理员账号来自共享后台账号表 t_admin_user。</li>
 *   <li>权限点来自 t_admin_menu.permission，并通过 t_admin_role_menu 绑定到 role。</li>
 *   <li>该 Mapper 用于 /oauth/check_token 自省时回填 authorities，让后台服务可以作为 OAuth2 资源服务。</li>
 * </ul>
 */
@Mapper
public interface AdminPermissionMapper {

    /**
     * 判断管理员是否属于系统级 super_admin 角色。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>super_admin 角色直接视为平台级最高权限。</li>
     *   <li>这样可以兼容后台账号表中 scope_type 与 tenant_id 仍在迁移中的场景。</li>
     * </ul>
     */
    @Select("""
            SELECT COUNT(1)
            FROM t_admin_user u
            INNER JOIN t_admin_role r ON u.role_id = r.id
            WHERE u.id = #{adminId}
              AND u.deleted = 0
              AND u.status = 1
              AND r.deleted = 0
              AND r.status = 1
              AND r.role_code = 'super_admin'
            """)
    int countCompatibleSuperAdminByAdminId(@Param("adminId") Long adminId);

    /**
     * 根据管理员 ID 查询权限列表。
     *
     * <p>注意：</p>
     * <ul>
     *   <li>只返回启用且未删除的菜单权限</li>
     *   <li>过滤空 permission</li>
     * </ul>
     */
    @Select("""
            SELECT m.permission
            FROM t_admin_user u
            INNER JOIN t_admin_role r ON u.role_id = r.id
            INNER JOIN t_admin_role_menu rm ON u.role_id = rm.role_id
            INNER JOIN t_admin_menu m ON m.id = rm.menu_id
            WHERE u.id = #{adminId}
              AND u.deleted = 0
              AND u.status = 1
              AND r.deleted = 0
              AND r.status = 1
              AND (
                    r.role_code = 'super_admin'
                 OR (u.scope_type = 'SYSTEM' AND u.tenant_id = 0)
                 OR (
                        u.scope_type = 'TENANT'
                    AND u.tenant_id = #{tenantId}
                    AND (
                            NOT EXISTS (
                                SELECT 1
                                FROM t_tenant_menu_scope scope_missing
                                WHERE scope_missing.tenant_id = #{tenantId}
                            )
                         OR EXISTS (
                                SELECT 1
                                FROM t_tenant_menu_scope scope
                                WHERE scope.tenant_id = #{tenantId}
                                  AND scope.menu_id = m.id
                            )
                    )
                 )
              )
              AND m.deleted = 0
              AND m.status = 1
              AND m.permission IS NOT NULL
              AND m.permission != ''
            """)
    List<String> selectPermissionsByAdminId(@Param("adminId") Long adminId, @Param("tenantId") Long tenantId);
}
