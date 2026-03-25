package com.bootcloud.common.core.security;

import java.util.Arrays;

/**
 * Base32 编解码工具（RFC 4648，无 padding）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用途：TOTP（RFC 6238）常用 Base32 存储 secret。</li>
 *   <li>实现目标：不引入额外三方依赖，保持服务端可控与可审计。</li>
 * </ul>
 */
public final class Base32Util {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    /**
     * 反向表：ASCII 0~127。
     * 值为 0~31 表示有效字符，-1 表示无效。
     */
    private static final int[] REVERSE = new int[128];

    static {
        Arrays.fill(REVERSE, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            REVERSE[ALPHABET[i]] = i;
        }
        // 兼容小写输入
        for (int i = 0; i < 26; i++) {
            REVERSE['a' + i] = REVERSE['A' + i];
        }
    }

    private Base32Util() {
    }

    /**
     * Base32 编码（无 padding）。
     */
    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int idx = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                out.append(ALPHABET[idx]);
            }
        }
        if (bitsLeft > 0) {
            int idx = (buffer << (5 - bitsLeft)) & 0x1F;
            out.append(ALPHABET[idx]);
        }
        return out.toString();
    }

    /**
     * Base32 解码（允许包含空格与连字符，允许小写，不接受 padding）。
     */
    public static byte[] decode(String base32) {
        if (base32 == null) {
            return new byte[0];
        }
        String s = base32.trim();
        if (s.isEmpty()) {
            return new byte[0];
        }

        int buffer = 0;
        int bitsLeft = 0;
        byte[] tmp = new byte[s.length() * 5 / 8 + 8];
        int outPos = 0;

        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == ' ' || ch == '-' || ch == '_') {
                continue;
            }
            if (ch >= REVERSE.length) {
                throw new IllegalArgumentException("Base32 输入包含非法字符");
            }
            int val = REVERSE[ch];
            if (val < 0) {
                throw new IllegalArgumentException("Base32 输入包含非法字符");
            }

            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                tmp[outPos++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }

        return Arrays.copyOf(tmp, outPos);
    }
}

