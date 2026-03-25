package com.bootcloud.common.core.security;

import com.bootcloud.common.core.error.AppException;
import com.bootcloud.common.core.error.CommonErrorCode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TOTP 工具（RFC 6238）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>默认参数：30 秒步长，6 位数字，HmacSHA1。</li>
 *   <li>服务端校验允许一定的时间漂移（通常 ±1 个步长），避免用户端时间略偏导致频繁失败。</li>
 * </ul>
 */
public final class TotpUtil {

    private TotpUtil() {
    }

    /**
     * 生成随机 TOTP secret，并用 Base32 表示（无 padding）。
     *
     * @param numBytes secret 原始字节长度，建议 16~32
     */
    public static String generateSecretBase32(int numBytes) {
        int n = Math.max(numBytes, 16);
        byte[] buf = new byte[n];
        new SecureRandom().nextBytes(buf);
        return Base32Util.encode(buf);
    }

    /**
     * 构造 otpauth URL，供前端生成二维码。
     *
     * <p>示例：</p>
     * otpauth://totp/{issuer}:{account}?secret=...&issuer=...
     */
    public static String buildOtpAuthUrl(String issuer, String account, String secretBase32) {
        String iss = safe(issuer);
        String acc = safe(account);
        String sec = safe(secretBase32);
        if (sec.isEmpty()) {
            throw new IllegalArgumentException("secretBase32 不能为空");
        }
        String label = urlEncode(iss) + ":" + urlEncode(acc);
        return "otpauth://totp/" + label
                + "?secret=" + urlEncode(sec)
                + "&issuer=" + urlEncode(iss)
                + "&algorithm=SHA1"
                + "&digits=6"
                + "&period=30";
    }

    /**
     * 校验 6 位 TOTP。
     *
     * @param allowedDriftSteps 允许时间漂移的步数（例如 1 表示允许前后各 30 秒）
     */
    public static boolean verifyCode(String secretBase32, String code, long nowMillis, int allowedDriftSteps) {
        String c = normalizeCode(code);
        if (c.length() != 6) {
            return false;
        }
        long timeStep = (nowMillis / 1000L) / 30L;
        int drift = Math.max(allowedDriftSteps, 0);
        for (long i = -drift; i <= drift; i++) {
            String expected = generateCode(secretBase32, timeStep + i);
            if (c.equals(expected)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 生成某个时间步的 6 位验证码（仅用于服务端计算与校验）。
     */
    public static String generateCode(String secretBase32, long timeStep) {
        byte[] key = Base32Util.decode(secretBase32);
        byte[] msg = new byte[8];
        long v = timeStep;
        for (int i = 7; i >= 0; i--) {
            msg[i] = (byte) (v & 0xFF);
            v >>= 8;
        }
        byte[] hash = hmacSha1(key, msg);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int otp = binary % 1_000_000;
        return String.format("%06d", otp);
    }

    public static String normalizeCode(String code) {
        if (code == null) {
            return "";
        }
        // 用户输入经常包含空格或短横线，统一去掉
        String s = code.trim().replace(" ", "").replace("-", "");
        return s;
    }

    private static byte[] hmacSha1(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(msg);
        } catch (Exception e) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("module", "TotpUtil");
            details.put("operation", "hmacSha1");
            throw new AppException(CommonErrorCode.SERVER_ERROR, "HMAC 计算失败", null, details, e);
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}
