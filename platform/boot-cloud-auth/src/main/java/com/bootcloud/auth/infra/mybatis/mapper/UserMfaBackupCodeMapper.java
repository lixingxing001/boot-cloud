package com.bootcloud.auth.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.auth.infra.mybatis.entity.UserMfaBackupCodeEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMfaBackupCodeMapper extends BaseMapper<UserMfaBackupCodeEntity> {
}

