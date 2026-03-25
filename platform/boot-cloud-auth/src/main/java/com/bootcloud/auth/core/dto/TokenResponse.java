package com.bootcloud.auth.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenResponse {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType = "bearer";

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

    private String scope;

    public static TokenResponse of(String accessToken, long expiresIn, String refreshToken, String scope) {
        TokenResponse r = new TokenResponse();
        r.accessToken = accessToken;
        r.expiresIn = expiresIn;
        r.refreshToken = refreshToken;
        r.scope = scope;
        return r;
    }
}
