package com.bootcloud.base.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.base.infra.mybatis.entity.TenantDomainEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TenantDomainMapper extends BaseMapper<TenantDomainEntity> {
}

