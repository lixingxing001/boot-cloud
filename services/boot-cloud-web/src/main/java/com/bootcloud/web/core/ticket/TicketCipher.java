package com.bootcloud.web.core.ticket;

import java.util.Map;

/**
 * state/ticket 加密接口（BFF 内部使用）。
 */
public interface TicketCipher {

    String encrypt(Map<String, Object> payload);

    Map<String, Object> decrypt(String token);

    void assertNotExpired(Map<String, Object> payload, long nowEpochSeconds);

    long nowEpochSeconds();
}

