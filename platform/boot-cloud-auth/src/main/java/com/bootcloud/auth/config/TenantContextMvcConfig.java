package com.bootcloud.auth.config;

import com.bootcloud.auth.core.tenant.TenantContextInterceptor;
import com.bootcloud.auth.core.tenant.TenantResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC 拦截器注册：只对 {@code /oauth/**} 注入租户上下文。
 */
@Configuration
public class TenantContextMvcConfig implements WebMvcConfigurer {

    private final TenantResolver tenantResolver;

    public TenantContextMvcConfig(TenantResolver tenantResolver) {
        this.tenantResolver = tenantResolver;
    }

    @Bean
    public TenantContextInterceptor tenantContextInterceptor() {
        return new TenantContextInterceptor(tenantResolver);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(tenantContextInterceptor())
                // /oauth/**：OAuth2 端点（token/code/refresh/introspect/revoke）
                // /api/auth/**：认证扩展端点（示例登录、设备管理等）
                .addPathPatterns("/oauth/**", "/api/auth/**");
    }
}
