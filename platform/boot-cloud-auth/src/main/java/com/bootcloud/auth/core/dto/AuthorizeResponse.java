package com.bootcloud.auth.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizeResponse {
    private String code;
    private String state;
    private String redirect;

    public static AuthorizeResponse ok(String code, String state, String redirect) {
        AuthorizeResponse r = new AuthorizeResponse();
        r.code = code;
        r.state = state;
        r.redirect = redirect;
        return r;
    }
}

