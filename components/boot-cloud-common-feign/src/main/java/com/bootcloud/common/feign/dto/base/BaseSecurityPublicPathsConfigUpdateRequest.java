package com.bootcloud.common.feign.dto.base;

import lombok.Data;

import java.util.List;

/**
 * 公共白名单路径更新请求。
 */
@Data
public class BaseSecurityPublicPathsConfigUpdateRequest {

    /**
     * 全量公共白名单路径。
     */
    private List<String> publicPaths;

    /**
     * 更新人。
     */
    private String updatedBy;

    /**
     * 更新备注。
     */
    private String remark;
}
