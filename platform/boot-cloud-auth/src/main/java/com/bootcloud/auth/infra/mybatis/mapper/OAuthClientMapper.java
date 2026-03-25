package com.bootcloud.auth.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.auth.infra.mybatis.entity.OAuthClientEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface OAuthClientMapper extends BaseMapper<OAuthClientEntity> {
}

