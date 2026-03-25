package com.bootcloud.auth.core.tenant;

import jakarta.servlet.http.HttpServletRequest;

public interface TenantResolver {
    long resolveTenantId(HttpServletRequest request);
}

