package com.bootcloud.auth.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.auth.infra.mybatis.entity.AuthTenantEntity;
import org.apache.ibatis.annotations.Mapper;

/**
 * 租户 Mapper（认证中心侧）。
 */
@Mapper
public interface AuthTenantMapper extends BaseMapper<AuthTenantEntity> {
}
