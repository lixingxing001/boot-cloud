package com.bootcloud.base.core.tenant;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * 域名解析租户的返回结构。
 *
 * <p>说明：这是给网关调用的“内部接口”返回值，字段尽量稳定，便于网关做本地缓存。</p>
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TenantResolveResult {

    @JsonProperty("tenant_id")
    private long tenantId;

    private String domain;

    private boolean fromDefault;

    public static TenantResolveResult of(long tenantId, String domain, boolean fromDefault) {
        TenantResolveResult r = new TenantResolveResult();
        r.tenantId = tenantId;
        r.domain = domain;
        r.fromDefault = fromDefault;
        return r;
    }
}

