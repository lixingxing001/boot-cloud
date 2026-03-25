package com.bootcloud.web.config.feign;

import com.bootcloud.web.config.UpstreamProperties;
import feign.Request;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;

import java.util.concurrent.TimeUnit;

/**
 * boot-cloud-web 调用 boot-cloud-auth 的 Feign 配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>保持与原 RestTemplate 版本一致的超时语义，避免上游抖动导致线程长期占用。</li>
 * </ul>
 */
@Slf4j
public class WebAuthFeignConfiguration {

    @Bean
    public Request.Options evmWebAuthFeignOptions(UpstreamProperties props) {
        long connectMs = props == null || props.getConnectTimeout() == null ? 3000L : props.getConnectTimeout().toMillis();
        long readMs = props == null || props.getReadTimeout() == null ? 10000L : props.getReadTimeout().toMillis();

        if (props != null && props.isDebugLog()) {
            log.info("boot-cloud-web Feign 超时配置: connectTimeoutMs={}, readTimeoutMs={}", connectMs, readMs);
        }

        return new Request.Options(
                connectMs, TimeUnit.MILLISECONDS,
                readMs, TimeUnit.MILLISECONDS,
                true
        );
    }
}

