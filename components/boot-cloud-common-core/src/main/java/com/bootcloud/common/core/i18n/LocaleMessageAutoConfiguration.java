package com.bootcloud.common.core.i18n;

import com.bootcloud.common.core.error.ErrorMessageResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;

/**
 * i18n 自动配置。
 */
@AutoConfiguration
@EnableConfigurationProperties(LocaleMessageProperties.class)
@ConditionalOnProperty(prefix = "boot.cloud.i18n", name = "enabled", havingValue = "true", matchIfMissing = true)
public class LocaleMessageAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(LocaleMessageAutoConfiguration.class);

    @Bean("evmErrorMessageSource")
    @ConditionalOnMissingBean(name = "evmErrorMessageSource")
    public MessageSource evmErrorMessageSource(LocaleMessageProperties properties) {
        ReloadableResourceBundleMessageSource source = new ReloadableResourceBundleMessageSource();
        source.setBasenames(properties.getBasenames().toArray(new String[0]));
        source.setDefaultEncoding(properties.getEncoding());
        source.setFallbackToSystemLocale(properties.isFallbackToSystemLocale());
        source.setUseCodeAsDefaultMessage(true);

        log.info("i18n 消息源已启用，basenames={}, defaultLocale={}, supportedLocales={}",
                properties.getBasenames(), properties.getDefaultLocale(), properties.getSupportedLocales());
        return source;
    }

    @Bean
    @ConditionalOnMissingBean
    public LocaleRequestResolver evmLocaleResolver(LocaleMessageProperties properties) {
        return new LocaleRequestResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ErrorMessageResolver errorMessageResolver(
            @Qualifier("evmErrorMessageSource") MessageSource messageSource,
            LocaleRequestResolver localeResolver) {
        return new ErrorMessageResolver(messageSource, localeResolver);
    }
}
