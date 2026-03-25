package com.bootcloud.common.feign.config;

import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;
import feign.form.spring.SpringFormEncoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.cloud.openfeign.support.SpringEncoder;
import org.springframework.context.annotation.Bean;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;

/**
 * Feign 表单编码配置。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于 {@code application/x-www-form-urlencoded} 的调用（典型场景：{@code /oauth/token} 与 {@code /oauth/check_token}）。</li>
 *   <li>避免 MultiValueMap 未按表单写入请求体，导致服务端解析不到 {@code @RequestParam} 必填参数。</li>
 * </ul>
 *
 * <p>使用方式：</p>
 * <ul>
 *   <li>在 {@code @FeignClient(configuration = ...)} 中显式引用本配置类。</li>
 *   <li>建议仅给 OAuth2 端点使用，减少对其它 JSON 调用的影响面。</li>
 * </ul>
 */
@Slf4j
public class FeignFormSupportConfiguration {

    @Bean
    public Encoder feignFormEncoder(ObjectFactory<HttpMessageConverters> messageConverters) {
        // 说明：
        // SpringFormEncoder 会优先处理表单场景，非表单内容会回退到 SpringEncoder。
        Encoder delegate = new SpringFormEncoder(new SpringEncoder(messageConverters));
        return new SafeFormStringEncoder(delegate);
    }

    /**
     * 兼容性 Encoder。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>背景：我们在迁移到 OpenFeign 后，发现少量环境里表单请求体可能被编码器遗漏，导致服务端拿不到 {@code @RequestParam} 的必填参数。</li>
     *   <li>方案：当 Content Type 为 {@code application/x-www-form-urlencoded} 且 body 是 String 时，强制把字符串作为请求体写入。</li>
     *   <li>安全：只记录 body 长度与方法信息，不记录 token 明文或密码。</li>
     * </ul>
     */
    static final class SafeFormStringEncoder implements Encoder {
        private final Encoder delegate;

        SafeFormStringEncoder(Encoder delegate) {
            this.delegate = delegate;
        }

        @Override
        public void encode(Object object, Type bodyType, RequestTemplate template) throws EncodeException {
            if (object instanceof String body && isFormUrlEncoded(template)) {
                if (log.isDebugEnabled()) {
                    log.debug("Feign 表单字符串编码器生效: method={}, url={}, bodyLen={}",
                            template == null ? "" : template.method(),
                            template == null ? "" : template.url(),
                            body.length());
                }
                template.body(body.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
                return;
            }
            delegate.encode(object, bodyType, template);
        }

        private static boolean isFormUrlEncoded(RequestTemplate template) {
            if (template == null) {
                return false;
            }
            Map<String, Collection<String>> headers = template.headers();
            if (headers == null || headers.isEmpty()) {
                return false;
            }
            for (Map.Entry<String, Collection<String>> e : headers.entrySet()) {
                String k = e.getKey();
                if (k == null) {
                    continue;
                }
                if (!"Content-Type".equalsIgnoreCase(k)) {
                    continue;
                }
                Collection<String> values = e.getValue();
                if (values == null || values.isEmpty()) {
                    return false;
                }
                for (String v : values) {
                    if (v == null) {
                        continue;
                    }
                    String low = v.toLowerCase();
                    if (low.contains("application/x-www-form-urlencoded")) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
