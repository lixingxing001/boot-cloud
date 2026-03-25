package com.bootcloud.common.feign.dto.base;

import java.io.Serial;
import java.io.Serializable;

/**
 * 平台默认租户更新请求 DTO。
 */
public class BaseDefaultTenantUpdateRequest implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 目标默认租户 ID。
     */
    private Long tenantId;

    public Long getTenantId() {
        return tenantId;
    }

    public void setTenantId(Long tenantId) {
        this.tenantId = tenantId;
    }
}
