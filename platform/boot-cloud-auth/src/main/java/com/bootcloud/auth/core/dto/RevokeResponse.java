package com.bootcloud.auth.core.dto;

import lombok.Data;

@Data
public class RevokeResponse {
    private boolean revoked;

    public static RevokeResponse ok(boolean revoked) {
        RevokeResponse r = new RevokeResponse();
        r.revoked = revoked;
        return r;
    }
}

