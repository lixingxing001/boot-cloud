package com.bootcloud.web.controller;

import com.bootcloud.common.core.api.ApiResponse;
import com.bootcloud.common.core.security.SecurityUserUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/web/demo")
public class DemoBffController {

    @GetMapping("/current/user")
    public ApiResponse<Object> currentUser() {
        Long userId = SecurityUserUtils.requireUserId();
        Long tenantId = SecurityUserUtils.requireTenantId();
        return ApiResponse.success(Map.of(
                "userId", userId,
                "tenantId", tenantId
        ));
    }
}
