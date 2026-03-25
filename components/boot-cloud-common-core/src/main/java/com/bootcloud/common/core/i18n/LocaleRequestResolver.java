package com.bootcloud.common.core.i18n;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 请求语言解析器。
 *
 * <p>解析顺序：</p>
 * <ul>
 *   <li>优先解析请求头 Accept-Language。</li>
 *   <li>其次使用 LocaleContextHolder 当前语言。</li>
 *   <li>最后回退到配置默认语言。</li>
 * </ul>
 */
public class LocaleRequestResolver {

    private static final Logger log = LoggerFactory.getLogger(LocaleRequestResolver.class);

    private final LocaleMessageProperties properties;
    private final Locale defaultLocale;
    private final List<Locale> supportedLocales;

    public LocaleRequestResolver(LocaleMessageProperties properties) {
        this.properties = properties;
        this.defaultLocale = parseLocale(properties.getDefaultLocale(), Locale.SIMPLIFIED_CHINESE);

        List<Locale> locales = new ArrayList<>();
        if (properties.getSupportedLocales() != null) {
            for (String item : properties.getSupportedLocales()) {
                Locale parsed = parseLocale(item, null);
                if (parsed != null) {
                    locales.add(parsed);
                }
            }
        }
        if (locales.isEmpty()) {
            locales.add(defaultLocale);
        }
        this.supportedLocales = List.copyOf(locales);
    }

    /**
     * 解析当前请求语言。
     */
    public Locale resolve(Object request) {
        Locale fromHeader = resolveFromHeader(resolveAcceptLanguageHeader(request));
        if (fromHeader != null) {
            if (properties.isDebugLog()) {
                log.debug("i18n 语言解析：from=header, locale={}", fromHeader.toLanguageTag());
            }
            return fromHeader;
        }

        Locale holderLocale = LocaleContextHolder.getLocale();
        Locale fromHolder = matchSupported(holderLocale);
        if (fromHolder != null) {
            if (properties.isDebugLog()) {
                log.debug("i18n 语言解析：from=holder, locale={}", fromHolder.toLanguageTag());
            }
            return fromHolder;
        }

        if (properties.isDebugLog()) {
            log.debug("i18n 语言解析：from=default, locale={}", defaultLocale.toLanguageTag());
        }
        return defaultLocale;
    }

    /**
     * 按 Accept-Language 字符串解析语言。
     */
    public Locale resolveFromHeader(String header) {
        if (!StringUtils.hasText(header)) {
            return null;
        }
        try {
            List<Locale.LanguageRange> ranges = Locale.LanguageRange.parse(header);
            Locale matched = Locale.lookup(ranges, supportedLocales);
            if (matched != null) {
                return matched;
            }
        } catch (IllegalArgumentException ignore) {
            if (properties.isDebugLog()) {
                log.debug("i18n 语言头解析失败，header={}", header);
            }
        }
        return null;
    }

    /**
     * 从不同请求对象中提取 Accept-Language，兼容 Servlet/WebFlux 运行时。
     */
    private String resolveAcceptLanguageHeader(Object request) {
        if (request == null) {
            return null;
        }
        if (request instanceof CharSequence sequence) {
            return sequence.toString();
        }

        String header = invokeGetHeader(request, "Accept-Language");
        if (StringUtils.hasText(header)) {
            return header;
        }

        Object headersObj = invokeNoArg(request, "getHeaders");
        if (headersObj != null) {
            String fromHeaders = invokeGetFirst(headersObj, "Accept-Language");
            if (StringUtils.hasText(fromHeaders)) {
                return fromHeaders;
            }
        }
        return null;
    }

    private static String invokeGetHeader(Object target, String name) {
        try {
            Method method = target.getClass().getMethod("getHeader", String.class);
            Object value = method.invoke(target, name);
            return value == null ? null : String.valueOf(value);
        } catch (Exception ignore) {
            return null;
        }
    }

    private static Object invokeNoArg(Object target, String methodName) {
        try {
            Method method = target.getClass().getMethod(methodName);
            return method.invoke(target);
        } catch (Exception ignore) {
            return null;
        }
    }

    private static String invokeGetFirst(Object headersObj, String name) {
        try {
            Method method = headersObj.getClass().getMethod("getFirst", String.class);
            Object value = method.invoke(headersObj, name);
            return value == null ? null : String.valueOf(value);
        } catch (Exception ignore) {
            return null;
        }
    }

    private Locale matchSupported(Locale locale) {
        if (locale == null) {
            return null;
        }
        for (Locale supported : supportedLocales) {
            if (supported.equals(locale)) {
                return supported;
            }
            if (supported.getLanguage().equalsIgnoreCase(locale.getLanguage())) {
                return supported;
            }
        }
        return null;
    }

    private static Locale parseLocale(String raw, Locale fallback) {
        if (!StringUtils.hasText(raw)) {
            return fallback;
        }
        Locale locale = Locale.forLanguageTag(raw.trim());
        if (!StringUtils.hasText(locale.getLanguage())) {
            return fallback;
        }
        return locale;
    }
}
