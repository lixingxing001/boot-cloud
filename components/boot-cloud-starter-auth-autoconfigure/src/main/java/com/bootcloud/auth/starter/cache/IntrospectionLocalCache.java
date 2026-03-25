package com.bootcloud.auth.starter.cache;

import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.LongConsumer;
import java.util.function.ToLongFunction;

/**
 * OAuth2 introspection 本地缓存工具。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>目标：统一各服务对本地 introspection cache 的 key、TTL、过期淘汰与容量控制逻辑。</li>
 *   <li>边界：这里只处理本地内存缓存，不关心具体调用 boot-cloud-auth 的协议细节。</li>
 * </ul>
 *
 * @param <T> 缓存值类型，例如 principal、IntrospectResponse、自定义 introspection DTO
 */
public class IntrospectionLocalCache<T> {

    private final String cacheName;
    private final Logger log;
    private final BooleanSupplier enabledSupplier;
    private final LongSupplier ttlSecondsSupplier;
    private final IntSupplier maxEntriesSupplier;
    private final Predicate<T> cacheablePredicate;
    private final ToLongFunction<T> expireAtEpochSecondExtractor;
    private final Runnable hitCallback;
    private final Runnable missCallback;
    private final Runnable putCallback;
    private final LongConsumer evictCallback;
    private final Map<String, CacheEntry<T>> cache = new ConcurrentHashMap<>();

    public IntrospectionLocalCache(
            String cacheName,
            Logger log,
            BooleanSupplier enabledSupplier,
            LongSupplier ttlSecondsSupplier,
            IntSupplier maxEntriesSupplier,
            Predicate<T> cacheablePredicate,
            ToLongFunction<T> expireAtEpochSecondExtractor
    ) {
        this(
                cacheName,
                log,
                enabledSupplier,
                ttlSecondsSupplier,
                maxEntriesSupplier,
                cacheablePredicate,
                expireAtEpochSecondExtractor,
                null,
                null,
                null,
                null
        );
    }

    public IntrospectionLocalCache(
            String cacheName,
            Logger log,
            BooleanSupplier enabledSupplier,
            LongSupplier ttlSecondsSupplier,
            IntSupplier maxEntriesSupplier,
            Predicate<T> cacheablePredicate,
            ToLongFunction<T> expireAtEpochSecondExtractor,
            Runnable hitCallback,
            Runnable missCallback,
            Runnable putCallback,
            LongConsumer evictCallback
    ) {
        this.cacheName = hasText(cacheName) ? cacheName.trim() : "introspection";
        this.log = log;
        this.enabledSupplier = enabledSupplier;
        this.ttlSecondsSupplier = ttlSecondsSupplier;
        this.maxEntriesSupplier = maxEntriesSupplier;
        this.cacheablePredicate = cacheablePredicate;
        this.expireAtEpochSecondExtractor = expireAtEpochSecondExtractor;
        this.hitCallback = hitCallback;
        this.missCallback = missCallback;
        this.putCallback = putCallback;
        this.evictCallback = evictCallback;
    }

    /**
     * 查询缓存。
     */
    public T get(String tenantId, String token) {
        if (!isEnabled() || !hasText(tenantId) || !hasText(token)) {
            return null;
        }

        String key = buildCacheKey(tenantId, token);
        CacheEntry<T> entry = cache.get(key);
        if (entry == null) {
            fire(hitCallback, false);
            fire(missCallback, true);
            return null;
        }

        long now = Instant.now().getEpochSecond();
        if (entry.expireAtEpochSecond <= now) {
            cache.remove(key);
            fireEvict(1L);
            fire(hitCallback, false);
            fire(missCallback, true);
            return null;
        }
        fire(hitCallback, true);
        fire(missCallback, false);
        return entry.value;
    }

    /**
     * 写入缓存。
     *
     * <p>说明：TTL 取“配置上限”和“token 剩余有效期”的最小值。</p>
     */
    public boolean put(String tenantId, String token, T value) {
        if (!isEnabled() || !hasText(tenantId) || !hasText(token) || value == null) {
            return false;
        }
        if (cacheablePredicate != null && !cacheablePredicate.test(value)) {
            return false;
        }

        long ttlByConfig = safePositive(ttlSecondsSupplier == null ? 0L : ttlSecondsSupplier.getAsLong(), 15L);
        int maxEntries = (int) safePositive(maxEntriesSupplier == null ? 0L : maxEntriesSupplier.getAsInt(), 20000L);
        long now = Instant.now().getEpochSecond();

        long expireAtEpochSecond = expireAtEpochSecondExtractor == null ? 0L : expireAtEpochSecondExtractor.applyAsLong(value);
        long ttlByToken = expireAtEpochSecond > 0 ? expireAtEpochSecond - now : Long.MAX_VALUE;
        long ttl = Math.min(ttlByConfig, ttlByToken);
        if (ttl <= 0) {
            if (log != null && log.isDebugEnabled()) {
                log.debug("{} introspection cache skip: tenantId={}, ttlSeconds={}, exp={}",
                        cacheName, tenantId, ttl, expireAtEpochSecond);
            }
            return false;
        }

        if (cache.size() >= maxEntries) {
            evictExpired(now);
            if (cache.size() >= maxEntries) {
                String first = cache.keySet().stream().findFirst().orElse(null);
                if (first != null) {
                    cache.remove(first);
                    fireEvict(1L);
                }
            }
        }

        cache.put(buildCacheKey(tenantId, token), new CacheEntry<>(value, now + ttl));
        fire(putCallback, true);
        if (log != null && log.isDebugEnabled()) {
            log.debug("{} introspection cache put: tenantId={}, ttlSeconds={}, exp={}",
                    cacheName, tenantId, ttl, expireAtEpochSecond);
        }
        return true;
    }

    /**
     * 主动清理过期条目。
     */
    public void evictExpired() {
        evictExpired(Instant.now().getEpochSecond());
    }

    private void evictExpired(long nowEpochSecond) {
        long removed = 0L;
        for (Map.Entry<String, CacheEntry<T>> entry : cache.entrySet()) {
            CacheEntry<T> value = entry.getValue();
            if (value == null || value.expireAtEpochSecond <= nowEpochSecond) {
                if (cache.remove(entry.getKey(), value)) {
                    removed++;
                }
            }
        }
        fireEvict(removed);
    }

    private boolean isEnabled() {
        return enabledSupplier == null || enabledSupplier.getAsBoolean();
    }

    private static String buildCacheKey(String tenantId, String token) {
        return tenantId.trim() + ":" + sha256Hex(token.trim());
    }

    private static long safePositive(long value, long fallback) {
        return value > 0 ? value : fallback;
    }

    private static boolean hasText(String raw) {
        return raw != null && !raw.trim().isEmpty();
    }

    /**
     * 说明：缓存 key 不再直接保留明文 token，降低堆转储与诊断快照中的敏感信息暴露面。
     */
    private static String sha256Hex(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private void fire(Runnable callback, boolean shouldRun) {
        if (shouldRun && callback != null) {
            callback.run();
        }
    }

    private void fireEvict(long removed) {
        if (removed > 0 && evictCallback != null) {
            evictCallback.accept(removed);
        }
    }

    private record CacheEntry<T>(T value, long expireAtEpochSecond) {
    }
}
