package com.bootcloud.common.core.trace;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * 自动为 WebClient.Builder 注入 TraceId 透传 filter。
 */
public class TraceIdWebClientBuilderBeanPostProcessor implements BeanPostProcessor {

    private static final Logger log = LoggerFactory.getLogger(TraceIdWebClientBuilderBeanPostProcessor.class);

    private final TraceProperties props;

    public TraceIdWebClientBuilderBeanPostProcessor(TraceProperties props) {
        this.props = props;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (!(bean instanceof WebClient.Builder builder)) {
            return bean;
        }
        if (props == null || !props.isEnabled()) {
            return bean;
        }

        builder.filter(new TraceIdWebClientCustomizer(props).asFilter());
        if (props.isStartupLog()) {
            log.info("WebClient.Builder 已注入 TraceId 透传能力：beanName={}, headerName={}", beanName, props.getHeaderName());
        }
        return builder;
    }
}

