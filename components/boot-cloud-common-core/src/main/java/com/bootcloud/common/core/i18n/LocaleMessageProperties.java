package com.bootcloud.common.core.i18n;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * i18n 通用配置。
 *
 * <p>配置项说明（nacos / application.yml 均可配置）：</p>
 * <ul>
 *   <li>boot.cloud.i18n.enabled：总开关，默认 true。</li>
 *   <li>boot.cloud.i18n.default-locale：默认语言，默认 zh-CN。</li>
 *   <li>boot.cloud.i18n.supported-locales：允许协商的语言列表。</li>
 *   <li>boot.cloud.i18n.basenames：消息资源 basename 列表。</li>
 *   <li>boot.cloud.i18n.debug-log：是否打印语言解析调试日志。</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "boot.cloud.i18n")
public class LocaleMessageProperties {

    /**
     * i18n 总开关。
     */
    private boolean enabled = true;

    /**
     * 默认语言。
     */
    private String defaultLocale = "zh-CN";

    /**
     * 支持的语言列表。
     */
    private List<String> supportedLocales = new ArrayList<>(Arrays.asList("zh-CN", "en-US"));

    /**
     * 资源文件 basename。
     */
    private List<String> basenames = new ArrayList<>(List.of("classpath:i18n/errors"));

    /**
     * 资源文件编码。
     */
    private String encoding = "UTF-8";

    /**
     * 是否启用系统语言回退。
     */
    private boolean fallbackToSystemLocale = false;

    /**
     * 调试日志开关。
     */
    private boolean debugLog = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDefaultLocale() {
        return defaultLocale;
    }

    public void setDefaultLocale(String defaultLocale) {
        this.defaultLocale = defaultLocale;
    }

    public List<String> getSupportedLocales() {
        return supportedLocales;
    }

    public void setSupportedLocales(List<String> supportedLocales) {
        this.supportedLocales = supportedLocales == null ? new ArrayList<>() : new ArrayList<>(supportedLocales);
    }

    public List<String> getBasenames() {
        return basenames;
    }

    public void setBasenames(List<String> basenames) {
        this.basenames = basenames == null ? new ArrayList<>() : new ArrayList<>(basenames);
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public boolean isFallbackToSystemLocale() {
        return fallbackToSystemLocale;
    }

    public void setFallbackToSystemLocale(boolean fallbackToSystemLocale) {
        this.fallbackToSystemLocale = fallbackToSystemLocale;
    }

    public boolean isDebugLog() {
        return debugLog;
    }

    public void setDebugLog(boolean debugLog) {
        this.debugLog = debugLog;
    }
}
