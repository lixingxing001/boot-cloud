package com.bootcloud.base.infra.mybatis.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bootcloud.base.infra.mybatis.entity.SystemConfigEntity;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 系统配置 Mapper。
 */
@Mapper
public interface SystemConfigMapper extends BaseMapper<SystemConfigEntity> {

    /**
     * 写入或更新平台默认租户配置。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>配置键固定唯一，可重复执行。</li>
     *   <li>只覆盖值与描述，不影响历史主键。</li>
     * </ul>
     */
    @Insert("""
            INSERT INTO t_system_config (config_key, config_value, description)
            VALUES (#{configKey}, #{configValue}, #{description})
            ON DUPLICATE KEY UPDATE
                config_value = VALUES(config_value),
                description = VALUES(description)
            """)
    int upsertConfig(@Param("configKey") String configKey,
                     @Param("configValue") String configValue,
                     @Param("description") String description);
}
