package com.bootcloud.web.config;

import com.bootcloud.web.core.version.VersionRefreshInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * boot-cloud-web MVC 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>统一注册客户端版本拦截器。</li>
 *   <li>拦截器内部会按配置决定是否生效，注册层保持简单。</li>
 * </ul>
 */
@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    private final VersionRefreshInterceptor versionRefreshInterceptor;

    public WebMvcConfiguration(VersionRefreshInterceptor versionRefreshInterceptor) {
        this.versionRefreshInterceptor = versionRefreshInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(versionRefreshInterceptor).addPathPatterns("/**");
    }
}
