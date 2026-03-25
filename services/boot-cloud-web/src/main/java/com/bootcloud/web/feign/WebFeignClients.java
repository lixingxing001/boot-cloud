package com.bootcloud.web.feign;

import com.bootcloud.common.feign.config.FeignFormSupportConfiguration;
import com.bootcloud.common.feign.api.AuthOAuthApi;
import com.bootcloud.common.feign.api.BaseTenantAdminApi;
import com.bootcloud.web.config.feign.WebAuthFeignConfiguration;
import com.bootcloud.web.config.feign.WebServiceFeignConfiguration;
import org.springframework.cloud.openfeign.FeignClient;

/**
 * boot-cloud-web Feign Client 声明。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot-cloud-web 作为 BFF，主要调用 boot-cloud-auth 的 /oauth/token。</li>
 *   <li>同一个 API 同时提供 LB 模式与直连模式，最终由动态工厂按 baseUrl 自动选择。</li>
 * </ul>
 */
public final class WebFeignClients {

    private WebFeignClients() {
    }

    @FeignClient(
            name = "boot-cloud-auth",
            contextId = "webAuthLoadBalancedClient",
            primary = false,
            configuration = {WebAuthFeignConfiguration.class, FeignFormSupportConfiguration.class}
    )
    public interface AuthLoadBalancedClient extends AuthOAuthApi {
    }

    @FeignClient(
            name = "boot-cloud-auth-direct",
            contextId = "webAuthDirectClient",
            primary = false,
            url = "${boot.cloud.auth.client.base-url:${boot.cloud.auth.client.base-url:http://boot-cloud-auth}}",
            configuration = {WebAuthFeignConfiguration.class, FeignFormSupportConfiguration.class}
    )
    public interface AuthDirectClient extends AuthOAuthApi {
    }

    /**
     * boot-cloud-base 内部租户管理接口。
     */
    @FeignClient(
            name = "${boot.cloud.web.services.base-service.service-name:boot-cloud-base}",
            contextId = "webBaseTenantAdminLoadBalancedClient",
            primary = false,
            configuration = WebServiceFeignConfiguration.class
    )
    public interface BaseTenantAdminLoadBalancedClient extends BaseTenantAdminApi {
    }

    @FeignClient(
            name = "boot-cloud-base-direct",
            contextId = "webBaseTenantAdminDirectClient",
            primary = false,
            url = "${boot.cloud.web.services.base-service.base-url:http://boot-cloud-base}",
            configuration = WebServiceFeignConfiguration.class
    )
    public interface BaseTenantAdminDirectClient extends BaseTenantAdminApi {
    }
}
