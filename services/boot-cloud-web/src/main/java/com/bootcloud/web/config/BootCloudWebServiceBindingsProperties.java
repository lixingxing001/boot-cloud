package com.bootcloud.web.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * boot-cloud-web 上游服务绑定配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>该配置专门承接“当前服务调用哪些上游服务”的绑定关系。</li>
 *   <li>与超时、日志等上游通用配置拆开，便于后续在不同项目里替换服务边界。</li>
 *   <li>当前脚手架只保留 BFF 必需的基础平台服务绑定。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "boot.cloud.web.services")
public class BootCloudWebServiceBindingsProperties {

    /**
     * 当前 BFF 服务名。
     */
    private String currentServiceName = "boot-cloud-web";

    /**
     * 平台基础服务。
     *
     * <p>示例职责：租户、域名映射、默认租户、公共路径配置等。</p>
     */
    private ServiceBinding baseService = new ServiceBinding("boot-cloud-base", "http://boot-cloud-base");

    @Data
    public static class ServiceBinding {

        private String serviceName;

        private String baseUrl;

        public ServiceBinding() {
        }

        public ServiceBinding(String serviceName, String baseUrl) {
            this.serviceName = serviceName;
            this.baseUrl = baseUrl;
        }
    }
}
