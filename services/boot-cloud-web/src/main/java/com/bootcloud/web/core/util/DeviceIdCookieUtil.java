package com.bootcloud.web.core.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * deviceId cookie 工具类。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用于“多会话”场景：同一账号多端同时在线，通过 deviceId 隔离 token 索引。</li>
 *   <li>deviceId 使用 HttpOnly cookie 保存，前端 JS 不读取。</li>
 *   <li>由于 Servlet Cookie API 不支持 SameSite，这里通过手工拼接 Set-Cookie 头实现。</li>
 * </ul>
 */
public final class DeviceIdCookieUtil {

    private static final Logger log = LoggerFactory.getLogger(DeviceIdCookieUtil.class);
    private static final String TOKEN_VERSION = "v1";

    private DeviceIdCookieUtil() {
    }

    public static String getOrCreateDeviceId(
            HttpServletRequest request,
            HttpServletResponse response,
            String cookieName,
            long maxAgeSeconds,
            String path,
            String sameSite,
            boolean secure,
            String domain,
            String tokenSecret
    ) {
        String name = StringUtils.hasText(cookieName) ? cookieName.trim() : "";
        if (!StringUtils.hasText(name)) {
            name = "BOOT_CLOUD_DEVICE_ID";
        }

        String rawCookie = readCookie(request, name);
        DecodedDeviceToken decoded = decodeDeviceToken(rawCookie, name, maxAgeSeconds, tokenSecret);
        if (decoded.valid()) {
            if (decoded.upgradedFromLegacy()) {
                writeSignedCookie(response, name, decoded.deviceId(), maxAgeSeconds, path, sameSite, secure, domain, tokenSecret);
                if (log.isInfoEnabled()) {
                    log.info("检测到旧版 deviceId cookie，已升级为签名 token：cookieName={}, deviceId={}",
                            name, maskDeviceId(decoded.deviceId()));
                }
            }
            return decoded.deviceId();
        }

        String newId = UUID.randomUUID().toString().replace("-", "");
        writeSignedCookie(response, name, newId, maxAgeSeconds, path, sameSite, secure, domain, tokenSecret);
        if (log.isDebugEnabled()) {
            log.debug("deviceId cookie 已创建：cookieName={}, deviceId={}, reason={}",
                    name, maskDeviceId(newId), decoded.reason());
        }
        return newId;
    }

    /**
     * 读取并校验 deviceId。
     *
     * <p>返回值说明：</p>
     * <ul>
     *   <li>返回非空：cookie 合法，或属于可兼容的旧版 raw deviceId。</li>
     *   <li>返回空：cookie 缺失、签名错误、格式错误或已过期。</li>
     * </ul>
     */
    public static String resolveDeviceId(HttpServletRequest request, String cookieName, long maxAgeSeconds, String tokenSecret) {
        String name = StringUtils.hasText(cookieName) ? cookieName.trim() : "";
        if (!StringUtils.hasText(name)) {
            name = "BOOT_CLOUD_DEVICE_ID";
        }
        String rawCookie = readCookie(request, name);
        DecodedDeviceToken decoded = decodeDeviceToken(rawCookie, name, maxAgeSeconds, tokenSecret);
        return decoded.valid() ? decoded.deviceId() : null;
    }

    public static String readCookie(HttpServletRequest request, String name) {
        if (request == null || !StringUtils.hasText(name)) {
            return null;
        }
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return null;
        }
        for (Cookie c : cookies) {
            if (c != null && name.equals(c.getName()) && StringUtils.hasText(c.getValue())) {
                return c.getValue();
            }
        }
        return null;
    }

    public static void clearCookie(HttpServletResponse response, String name, String path, String domain) {
        if (response == null || !StringUtils.hasText(name)) {
            return;
        }
        Cookie c = new Cookie(name.trim(), "");
        c.setPath(StringUtils.hasText(path) ? path.trim() : "/");
        if (StringUtils.hasText(domain)) {
            c.setDomain(domain.trim());
        }
        c.setMaxAge(0);
        response.addCookie(c);
    }

    /**
     * Servlet Cookie API 不支持 SameSite，因此这里手动拼 Set-Cookie。
     */
    public static void writeCookieWithSameSite(
            HttpServletResponse response,
            String name,
            String value,
            long maxAgeSeconds,
            String path,
            String sameSite,
            boolean secure,
            String domain
    ) {
        if (response == null || !StringUtils.hasText(name) || !StringUtils.hasText(value)) {
            return;
        }

        long maxAge = Math.max(maxAgeSeconds, 0);
        String cookiePath = StringUtils.hasText(path) ? path.trim() : "/";

        StringBuilder sb = new StringBuilder();
        sb.append(name.trim()).append("=").append(value.trim());
        sb.append("; Path=").append(cookiePath);
        sb.append("; Max-Age=").append(maxAge);
        sb.append("; HttpOnly");
        if (StringUtils.hasText(domain)) {
            sb.append("; Domain=").append(domain.trim());
        }
        if (secure) {
            sb.append("; Secure");
        }
        if (StringUtils.hasText(sameSite)) {
            sb.append("; SameSite=").append(sameSite.trim());
        }

        response.addHeader("Set-Cookie", sb.toString());
    }

    private static void writeSignedCookie(
            HttpServletResponse response,
            String name,
            String deviceId,
            long maxAgeSeconds,
            String path,
            String sameSite,
            boolean secure,
            String domain,
            String tokenSecret
    ) {
        String token = buildSignedToken(name, deviceId, tokenSecret);
        writeCookieWithSameSite(response, name, token, maxAgeSeconds, path, sameSite, secure, domain);
    }

    private static String buildSignedToken(String cookieName, String deviceId, String tokenSecret) {
        String issuedAtSeconds = String.valueOf(System.currentTimeMillis() / 1000);
        String signature = sign(cookieName, deviceId, issuedAtSeconds, tokenSecret);
        return TOKEN_VERSION + "." + deviceId + "." + issuedAtSeconds + "." + signature;
    }

    private static DecodedDeviceToken decodeDeviceToken(String rawCookie, String cookieName, long maxAgeSeconds, String tokenSecret) {
        if (!StringUtils.hasText(rawCookie)) {
            return DecodedDeviceToken.invalid("cookie_missing");
        }
        String value = rawCookie.trim();
        if (!value.startsWith(TOKEN_VERSION + ".")) {
            String legacy = safeDeviceId(value);
            if (!StringUtils.hasText(legacy)) {
                return DecodedDeviceToken.invalid("legacy_device_id_invalid");
            }
            return DecodedDeviceToken.legacy(legacy);
        }

        String[] parts = value.split("\\.");
        if (parts.length != 4) {
            return DecodedDeviceToken.invalid("token_format_invalid");
        }
        String deviceId = safeDeviceId(parts[1]);
        if (!StringUtils.hasText(deviceId)) {
            return DecodedDeviceToken.invalid("device_id_invalid");
        }

        long issuedAtSeconds;
        try {
            issuedAtSeconds = Long.parseLong(parts[2]);
        } catch (NumberFormatException e) {
            return DecodedDeviceToken.invalid("issued_at_invalid");
        }
        if (issuedAtSeconds <= 0) {
            return DecodedDeviceToken.invalid("issued_at_non_positive");
        }

        if (maxAgeSeconds > 0) {
            long ageSeconds = (System.currentTimeMillis() / 1000) - issuedAtSeconds;
            if (ageSeconds > maxAgeSeconds) {
                return DecodedDeviceToken.invalid("token_expired");
            }
        }

        String actualSignature = parts[3].trim();
        String expectedSignature = sign(cookieName, deviceId, parts[2].trim(), tokenSecret);
        if (!constantTimeEquals(expectedSignature, actualSignature)) {
            log.warn("deviceId token 签名校验失败：cookieName={}, deviceId={}", cookieName, maskDeviceId(deviceId));
            return DecodedDeviceToken.invalid("signature_invalid");
        }
        return DecodedDeviceToken.signed(deviceId);
    }

    private static String sign(String cookieName, String deviceId, String issuedAtSeconds, String tokenSecret) {
        if (!StringUtils.hasText(tokenSecret)) {
            throw new IllegalArgumentException("device token secret 不能为空");
        }
        String name = StringUtils.hasText(cookieName) ? cookieName.trim() : "BOOT_CLOUD_DEVICE_ID";
        String message = TOKEN_VERSION + ":" + name + ":" + deviceId + ":" + issuedAtSeconds;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(tokenSecret.trim().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            return bytesToHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("device token 签名失败", e);
        }
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (!StringUtils.hasText(expected) || !StringUtils.hasText(actual)) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.trim().getBytes(StandardCharsets.UTF_8),
                actual.trim().getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String safeDeviceId(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String value = raw.trim();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '_' || c == '-' || c == '.';
            if (ok) {
                sb.append(c);
            }
        }
        String out = sb.toString();
        if (!StringUtils.hasText(out)) {
            return null;
        }
        return out.length() <= 64 ? out : out.substring(0, 64);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static String maskDeviceId(String deviceId) {
        if (!StringUtils.hasText(deviceId)) {
            return "";
        }
        String value = deviceId.trim();
        if (value.length() <= 8) {
            return value;
        }
        return value.substring(0, 4) + "****" + value.substring(value.length() - 4);
    }

    private record DecodedDeviceToken(String deviceId, boolean valid, boolean upgradedFromLegacy, String reason) {
        private static DecodedDeviceToken invalid(String reason) {
            return new DecodedDeviceToken(null, false, false, reason);
        }

        private static DecodedDeviceToken legacy(String deviceId) {
            return new DecodedDeviceToken(deviceId, true, true, "legacy_cookie");
        }

        private static DecodedDeviceToken signed(String deviceId) {
            return new DecodedDeviceToken(deviceId, true, false, "signed_cookie");
        }
    }
}
