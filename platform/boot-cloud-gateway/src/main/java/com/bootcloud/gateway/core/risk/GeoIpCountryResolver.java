package com.bootcloud.gateway.core.risk;

import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.CountryResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 基于 MaxMind mmdb 的国家码解析器。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>只在网关本地做解析，不依赖外部网络调用。</li>
 *   <li>支持按文件变更自动重载，便于数据库定期更新。</li>
 *   <li>解析失败时返回空，不中断主请求链路。</li>
 * </ul>
 */
@Component
public class GeoIpCountryResolver {

    private static final Logger log = LoggerFactory.getLogger(GeoIpCountryResolver.class);

    // 说明：缓存已告警的键，避免同类问题刷屏。
    private final Set<String> warnedKeys = ConcurrentHashMap.newKeySet();
    private final AtomicReference<ReaderHolder> holderRef = new AtomicReference<>();
    private final Object reloadLock = new Object();

    /**
     * 解析国家码（ISO 3166-1 alpha-2）。
     *
     * @param clientIp 客户端 IP
     * @param mmdbPath 本地 mmdb 文件路径
     * @return 国家码，如 US/SG/CN；无法识别时返回 null
     */
    public String resolveCountry(String clientIp, String mmdbPath) {
        if (!StringUtils.hasText(clientIp) || !StringUtils.hasText(mmdbPath)) {
            return null;
        }

        DatabaseReader reader = ensureReader(mmdbPath);
        if (reader == null) {
            return null;
        }

        InetAddress ipAddress;
        try {
            ipAddress = InetAddress.getByName(clientIp.trim());
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("[gate-shield] GeoIP 跳过，IP 非法：ip={}, err={}", clientIp, e.getMessage());
            }
            return null;
        }

        try {
            CountryResponse response = reader.country(ipAddress);
            String iso = response == null || response.getCountry() == null
                    ? null
                    : response.getCountry().getIsoCode();
            return normalizeCountry(iso);
        } catch (AddressNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("[gate-shield] GeoIP 未命中国家：ip={}", clientIp);
            }
            return null;
        } catch (Exception e) {
            warnOnce("geoip_lookup_error|" + e.getClass().getSimpleName(),
                    "[gate-shield] GeoIP 查询失败，将按未知国家处理：ip={}, err={}", clientIp, e.getMessage());
            return null;
        }
    }

    private DatabaseReader ensureReader(String mmdbPath) {
        Path path = normalizePath(mmdbPath);
        if (path == null) {
            return null;
        }
        if (!Files.exists(path) || !Files.isReadable(path)) {
            warnOnce("geoip_path_unreadable|" + path,
                    "[gate-shield] GeoIP 数据库不可读，已跳过：path={}", path);
            return null;
        }

        long lastModified;
        try {
            lastModified = Files.getLastModifiedTime(path).toMillis();
        } catch (IOException e) {
            warnOnce("geoip_mtime_error|" + path,
                    "[gate-shield] GeoIP 读取文件时间戳失败，已跳过：path={}, err={}", path, e.getMessage());
            return null;
        }

        ReaderHolder current = holderRef.get();
        if (current != null && current.matches(path, lastModified)) {
            return current.reader();
        }

        synchronized (reloadLock) {
            current = holderRef.get();
            if (current != null && current.matches(path, lastModified)) {
                return current.reader();
            }
            DatabaseReader next;
            try {
                // 说明：CHMCache 可减少重复查找开销，适合网关高并发场景。
                next = new DatabaseReader.Builder(path.toFile())
                        .withCache(new CHMCache())
                        .build();
            } catch (IOException e) {
                warnOnce("geoip_open_error|" + path,
                        "[gate-shield] GeoIP 打开数据库失败，已跳过：path={}, err={}", path, e.getMessage());
                return null;
            }

            ReaderHolder prev = holderRef.getAndSet(new ReaderHolder(path, lastModified, next));
            closeQuietly(prev);
            log.info("[gate-shield] GeoIP 数据库已加载：path={}, lastModified={}", path, lastModified);
            return next;
        }
    }

    private void warnOnce(String key, String pattern, Object... args) {
        if (warnedKeys.add(key)) {
            log.warn(pattern, args);
        }
    }

    private static Path normalizePath(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        try {
            return Paths.get(raw.trim()).toAbsolutePath().normalize();
        } catch (Exception e) {
            return null;
        }
    }

    private static String normalizeCountry(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String code = raw.trim().toUpperCase(Locale.ROOT);
        return code.length() == 2 ? code : null;
    }

    @PreDestroy
    public void destroy() {
        closeQuietly(holderRef.getAndSet(null));
    }

    private static void closeQuietly(ReaderHolder holder) {
        if (holder == null || holder.reader() == null) {
            return;
        }
        try {
            holder.reader().close();
        } catch (Exception ignored) {
            // 说明：销毁阶段忽略关闭异常，避免影响应用退出流程。
        }
    }

    private record ReaderHolder(Path path, long lastModified, DatabaseReader reader) {
        private boolean matches(Path p, long mtime) {
            return path.equals(p) && lastModified == mtime;
        }
    }
}
