package com.bootcloud.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * boot-cloud-gateway 启动类。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>网关负责统一入口：路由、认证鉴权、租户解析与透传。</li>
 *   <li>本阶段策略：
 *     <ul>
 *       <li>token 校验：调用 boot-cloud-auth 的 /oauth/check_token（A 方案）。</li>
 *       <li>租户解析：调用 boot-cloud-base 的 /internal/tenant/resolve（按域名映射）。</li>
 *     </ul>
 *   </li>
 * </ul>
 */

@SpringBootApplication
@EnableScheduling
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}

