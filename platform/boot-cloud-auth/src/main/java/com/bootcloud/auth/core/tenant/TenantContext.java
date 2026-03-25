package com.bootcloud.auth.core.tenant;

/**
 * 租户上下文（ThreadLocal）。
 *
 * <p>设计说明：</p>
 * <ul>
 *   <li>Sa-Token OAuth2 的核心逻辑大量使用静态工具类（例如 SaOAuth2Util），并在内部拼接 Redis Key。</li>
 *   <li>为了让 OAuth2 的 code/token 在多租户场景下天然隔离，我们需要在“当前线程”能拿到 tenantId。</li>
 *   <li>脚手架默认 tenantId=1 作为兜底值，同时保留后续放开多租户的扩展空间。</li>
 * </ul>
 *
 * <p>注意：</p>
 * <ul>
 *   <li>一定要在请求结束时清理，避免线程复用导致的租户串扰。</li>
 * </ul>
 */
public final class TenantContext {

    private static final ThreadLocal<Long> TENANT_ID = new ThreadLocal<>();

    private TenantContext() {
    }

    public static void setTenantId(long tenantId) {
        TENANT_ID.set(tenantId);
    }

    /**
     * 获取当前线程上真实写入的 tenantId。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>返回 null 代表当前线程尚未写入租户上下文。</li>
     *   <li>该方法主要用于“临时切换会话租户后再恢复现场”的场景。</li>
     * </ul>
     */
    public static Long getTenantIdOrNull() {
        return TENANT_ID.get();
    }

    /**
     * 获取当前 tenantId。
     *
     * <p>这里提供默认值 1 的原因：</p>
     * <ul>
     *   <li>脚手架默认 tenantId=1 作为最小可用租户。</li>
     *   <li>避免某些非 HTTP 调用链路未设置上下文时出现 NPE。</li>
     * </ul>
     */
    public static long getTenantIdOrDefault() {
        Long v = TENANT_ID.get();
        return v == null ? 1L : v;
    }

    public static void clear() {
        TENANT_ID.remove();
    }
}

