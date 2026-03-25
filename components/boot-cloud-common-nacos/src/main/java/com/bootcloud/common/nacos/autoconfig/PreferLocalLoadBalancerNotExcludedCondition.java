package com.bootcloud.common.nacos.autoconfig;

import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 是否启用“本机优先负载均衡”的条件。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于在公共配置启用时排除特定应用，避免出现重复装配导致的冲突。</li>
 *   <li>典型：boot-cloud-gateway 自带增强版策略，因此公共模块默认排除 boot-cloud-gateway。</li>
 * </ul>
 */
public class PreferLocalLoadBalancerNotExcludedCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        if (context == null) {
            return true;
        }
        Environment env = context.getEnvironment();
        if (env == null) {
            return true;
        }

        String appName = env.getProperty("spring.application.name", "");
        if (!StringUtils.hasText(appName)) {
            return true;
        }

        List<String> excludes = Binder.get(env)
                .bind("boot.cloud.lb.prefer-local.exclude-applications", Bindable.listOf(String.class))
                .orElse(List.of("boot-cloud-gateway"));

        for (String s : excludes) {
            if (!StringUtils.hasText(s)) {
                continue;
            }
            if (appName.trim().equalsIgnoreCase(s.trim())) {
                return false;
            }
        }
        return true;
    }
}

