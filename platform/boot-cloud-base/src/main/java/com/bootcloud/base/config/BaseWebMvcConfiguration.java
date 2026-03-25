package com.bootcloud.base.config;

import com.bootcloud.base.core.web.InternalAdminAuthInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * WebMvc 配置：注册内部管理接口鉴权拦截器。
 */
@Configuration
public class BaseWebMvcConfiguration implements WebMvcConfigurer {

    private final InternalAdminAuthInterceptor internalAdminAuthInterceptor;

    public BaseWebMvcConfiguration(InternalAdminAuthInterceptor internalAdminAuthInterceptor) {
        this.internalAdminAuthInterceptor = internalAdminAuthInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 只保护 /internal/admin/**，不影响网关调用的 /internal/tenant/**。
        registry.addInterceptor(internalAdminAuthInterceptor)
                .addPathPatterns("/internal/admin/**");
    }
}

