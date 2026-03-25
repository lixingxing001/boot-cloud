package com.bootcloud.web.core.ticket;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * ticket/state 加密器（AES-256-GCM）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>避免把敏感字段（如第三方授权码）明文放在 URL 中。</li>
 *   <li>GCM 自带完整性校验，解密失败会直接抛异常。</li>
 * </ul>
 */
public class AesGcmTicketCipher implements TicketCipher {

    private static final Logger log = LoggerFactory.getLogger(AesGcmTicketCipher.class);

    private static final String ALG = "AES";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec keySpec;
    private final SecureRandom rng = new SecureRandom();
    private final ObjectMapper om = new ObjectMapper();

    public AesGcmTicketCipher(byte[] key) {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new IllegalArgumentException("AES key 长度必须为 16/24/32 bytes");
        }
        this.keySpec = new SecretKeySpec(key, ALG);
    }

    @Override
    public String encrypt(Map<String, Object> payload) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            rng.nextBytes(nonce);

            Cipher c = Cipher.getInstance(TRANSFORM);
            c.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(TAG_BITS, nonce));

            byte[] plain = om.writeValueAsBytes(payload);
            byte[] enc = c.doFinal(plain);

            // token = base64url(nonce || ciphertext)
            byte[] out = new byte[nonce.length + enc.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(enc, 0, out, nonce.length, enc.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("ticket 加密失败", e);
        }
    }

    @Override
    public Map<String, Object> decrypt(String token) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(token);
            if (raw.length <= NONCE_BYTES) {
                throw new IllegalArgumentException("token too short");
            }
            byte[] nonce = new byte[NONCE_BYTES];
            byte[] enc = new byte[raw.length - NONCE_BYTES];
            System.arraycopy(raw, 0, nonce, 0, NONCE_BYTES);
            System.arraycopy(raw, NONCE_BYTES, enc, 0, enc.length);

            Cipher c = Cipher.getInstance(TRANSFORM);
            c.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(TAG_BITS, nonce));

            byte[] plain = c.doFinal(enc);
            //noinspection unchecked
            return om.readValue(new String(plain, StandardCharsets.UTF_8), Map.class);
        } catch (Exception e) {
            // 这里记录 debug 日志，便于排查 ticket/state 失效问题
            log.debug("ticket 解密失败：{}", e.getMessage());
            throw new IllegalArgumentException("invalid ticket/state", e);
        }
    }

    @Override
    public void assertNotExpired(Map<String, Object> payload, long nowEpochSeconds) {
        Object exp = payload.get("exp");
        if (exp == null) {
            throw new IllegalArgumentException("missing exp");
        }
        long expSeconds = parseLong(exp);
        if (nowEpochSeconds > expSeconds) {
            throw new IllegalArgumentException("expired");
        }
        // 预留：如果未来需要 clock-skew，可在此处引入
    }

    @Override
    public long nowEpochSeconds() {
        return Instant.now().getEpochSecond();
    }

    private static long parseLong(Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }
}

