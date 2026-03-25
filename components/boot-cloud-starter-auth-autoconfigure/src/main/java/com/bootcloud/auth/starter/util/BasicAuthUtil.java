package com.bootcloud.auth.starter.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class BasicAuthUtil {

    private BasicAuthUtil() {
    }

    public static String basic(String clientId, String clientSecret) {
        String v = clientId + ":" + (clientSecret == null ? "" : clientSecret);
        String b64 = Base64.getEncoder().encodeToString(v.getBytes(StandardCharsets.UTF_8));
        return "Basic " + b64;
    }
}

