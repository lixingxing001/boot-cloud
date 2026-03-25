package com.bootcloud.common.core.error;

import com.bootcloud.common.core.i18n.LocaleRequestResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.util.StringUtils;

import java.util.Locale;

/**
 * 错误消息解析器。
 */
public class ErrorMessageResolver {

    private static final Logger log = LoggerFactory.getLogger(ErrorMessageResolver.class);

    private final MessageSource messageSource;
    private final LocaleRequestResolver localeResolver;

    public ErrorMessageResolver(MessageSource messageSource, LocaleRequestResolver localeResolver) {
        this.messageSource = messageSource;
        this.localeResolver = localeResolver;
    }

    /**
     * 按 ErrorCode 解析本地化文案。
     */
    public String resolve(Object request, ErrorCode code, Object... args) {
        if (code == null) {
            return "";
        }
        Locale locale = localeResolver.resolve(request);
        return resolveByKey(code.messageKey(), code.defaultMessage(), locale, args);
    }

    /**
     * 按字符串 code 解析文案，命中公共目录则返回本地化内容。
     */
    public String resolveByCode(Object request, String code, String fallbackMessage, Object... args) {
        Locale locale = localeResolver.resolve(request);
        CommonErrorCode mapped = CommonErrorCode.fromCode(code);
        if (mapped == null) {
            if (StringUtils.hasText(fallbackMessage)) {
                return fallbackMessage;
            }
            return code == null ? "" : code;
        }
        return resolveByKey(mapped.messageKey(), mapped.defaultMessage(), locale, args);
    }

    private String resolveByKey(String key, String defaultMessage, Locale locale, Object... args) {
        if (!StringUtils.hasText(key)) {
            return defaultMessage == null ? "" : defaultMessage;
        }
        try {
            return messageSource.getMessage(key, args, defaultMessage, locale);
        } catch (NoSuchMessageException e) {
            log.debug("i18n 资源缺失：key={}, locale={}", key, locale);
            return defaultMessage == null ? key : defaultMessage;
        }
    }
}
