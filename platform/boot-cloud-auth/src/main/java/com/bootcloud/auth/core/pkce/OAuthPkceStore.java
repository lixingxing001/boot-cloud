package com.bootcloud.auth.core.pkce;

import cn.dev33.satoken.dao.SaTokenDao;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * OAuth2 PKCE 绑定存储（基于 Sa-Token 的 Redis Dao）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>PKCE 绑定的是“授权码 code -> (challenge, method)”。</li>
 *   <li>授权码是一次性的，因此 PKCE 绑定也应当一次性消费（consume 后删除）。</li>
 *   <li>这里刻意使用 Sa-Token 的 {@link SaTokenDao}，保证与 OAuth2 code/token 使用同一个 Redis（alone-redis）。</li>
 * </ul>
 */
@Component
public class OAuthPkceStore {

    private static final String PREFIX = "bootcloud:oauth2:";

    private final SaTokenDao saTokenDao;

    public OAuthPkceStore(SaTokenDao saTokenDao) {
        this.saTokenDao = saTokenDao;
    }

    /**
     * 保存 PKCE 绑定（与 code 同 TTL）。
     */
    public void save(long tenantId, String code, String codeChallenge, String codeChallengeMethod, long ttlSeconds) {
        if (tenantId <= 0 || !StringUtils.hasText(code) || !StringUtils.hasText(codeChallenge)) {
            return;
        }
        String method = normalizeMethod(codeChallengeMethod);
        // 为了避免对象序列化的兼容性问题，直接存成紧凑字符串：method|challenge
        String value = method + "|" + codeChallenge.trim();
        saTokenDao.set(key(tenantId, code), value, ttlSeconds);
    }

    /**
     * 读取 PKCE 绑定（不删除）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>为了避免“前端签错一次就无法重试”的体验问题，这里读取不删除。</li>
     *   <li>校验通过后再调用 {@link #delete(long, String)} 删除，做到一次性消费、防重放。</li>
     * </ul>
     */
    public PkceBinding get(long tenantId, String code) {
        if (tenantId <= 0 || !StringUtils.hasText(code)) {
            return null;
        }
        String k = key(tenantId, code);
        String v = saTokenDao.get(k);
        if (!StringUtils.hasText(v)) {
            return null;
        }

        int idx = v.indexOf('|');
        if (idx <= 0 || idx >= v.length() - 1) {
            return null;
        }
        PkceBinding b = new PkceBinding();
        b.codeChallengeMethod = v.substring(0, idx);
        b.codeChallenge = v.substring(idx + 1);
        return b;
    }

    public boolean exists(long tenantId, String code) {
        if (tenantId <= 0 || !StringUtils.hasText(code)) {
            return false;
        }
        return StringUtils.hasText(saTokenDao.get(key(tenantId, code)));
    }

    public void delete(long tenantId, String code) {
        if (tenantId <= 0 || !StringUtils.hasText(code)) {
            return;
        }
        saTokenDao.delete(key(tenantId, code));
    }

    private static String key(long tenantId, String code) {
        return PREFIX + tenantId + ":pkce:" + code;
    }

    private static String normalizeMethod(String raw) {
        if (!StringUtils.hasText(raw)) {
            return "plain";
        }
        String m = raw.trim();
        if (m.equalsIgnoreCase("S256")) {
            return "S256";
        }
        return "plain";
    }

    public static class PkceBinding {
        public String codeChallenge;
        public String codeChallengeMethod;
    }
}
