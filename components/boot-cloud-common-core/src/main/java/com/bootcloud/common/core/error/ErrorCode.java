package com.bootcloud.common.core.error;

/**
 * 统一错误码契约。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>code：对外稳定输出，供前端或调用方做分支逻辑。</li>
 *   <li>messageKey：多语言资源 key，服务端据此解析本地化文案。</li>
 *   <li>defaultMessage：兜底文案，避免资源缺失时返回空消息。</li>
 * </ul>
 */
public interface ErrorCode {

    /**
     * 对外错误码。
     */
    String code();

    /**
     * i18n 资源 key。
     */
    String messageKey();

    /**
     * 资源缺失时的兜底文案。
     */
    String defaultMessage();
}
