package com.bootcloud.auth.starter.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * boot-cloud-auth /oauth/check_token 的响应结构（调用方 DTO）。
 */
@Data
public class IntrospectResponse {

    private boolean active;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("subject_type")
    private String subjectType;

    @JsonProperty("sub")
    private String userId;

    private String scope;

    private long exp;
}

