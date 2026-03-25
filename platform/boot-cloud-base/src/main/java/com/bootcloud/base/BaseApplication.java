package com.bootcloud.base;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * boot-cloud-base 启动类。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>boot-cloud-base 是“平台基础模块”，承载租户、域名映射、字典、参数等基础能力。</li>
 *   <li>网关（boot-cloud-gateway）会调用本服务来解析 tenantId（domain -> tenantId）。</li>
 * </ul>
 */
@SpringBootApplication
@MapperScan("com.bootcloud.base.infra.mybatis.mapper")
public class BaseApplication {

    public static void main(String[] args) {
        SpringApplication.run(BaseApplication.class, args);
    }
}

