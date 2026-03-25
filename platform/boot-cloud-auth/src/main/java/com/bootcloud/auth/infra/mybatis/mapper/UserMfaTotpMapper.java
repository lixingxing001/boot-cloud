package com.bootcloud.auth.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.auth.infra.mybatis.entity.UserMfaTotpEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMfaTotpMapper extends BaseMapper<UserMfaTotpEntity> {
}

