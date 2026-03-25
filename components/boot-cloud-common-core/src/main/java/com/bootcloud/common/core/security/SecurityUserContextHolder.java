package com.bootcloud.common.core.security;

/**
 * SecurityUserContext 的线程容器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>使用 ThreadLocal 存放，生命周期为单次请求。</li>
 *   <li>由自动注册的 Filter 在请求开始时 set，在请求结束时 clear。</li>
 * </ul>
 */
public final class SecurityUserContextHolder {

    private static final ThreadLocal<SecurityUserContext> HOLDER = new ThreadLocal<>();

    private SecurityUserContextHolder() {
    }

    public static void set(SecurityUserContext ctx) {
        HOLDER.set(ctx);
    }

    public static SecurityUserContext get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }
}
