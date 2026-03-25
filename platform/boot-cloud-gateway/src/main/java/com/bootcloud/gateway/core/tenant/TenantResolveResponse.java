package com.bootcloud.gateway.core.tenant;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * boot-cloud-base 的 tenant resolve 返回结构（网关侧 DTO）。
 */
@Data
public class TenantResolveResponse {

    @JsonProperty("tenant_id")
    private long tenantId;

    private String domain;

    private boolean fromDefault;
}

