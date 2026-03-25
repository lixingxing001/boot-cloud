package com.bootcloud.auth.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.auth.infra.mybatis.entity.AuthUser;
import org.apache.ibatis.annotations.Mapper;

/**
 * 用户最小查询 Mapper（用于 OAuth2 password grant）。
 */
@Mapper
public interface AuthUserMapper extends BaseMapper<AuthUser> {
}

