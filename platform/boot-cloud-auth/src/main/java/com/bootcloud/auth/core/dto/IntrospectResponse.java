package com.bootcloud.auth.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import cn.dev33.satoken.oauth2.model.AccessTokenModel;
import cn.dev33.satoken.oauth2.model.ClientTokenModel;
import com.bootcloud.auth.core.token.OAuthAccessToken;
import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
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

    /**
     * 权限列表（用于资源服务鉴权）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该字段主要给后台资源服务（管理端服务）使用：把权限点映射成 GrantedAuthority。</li>
     *   <li>仅在 admin scope 的 token 自省时返回，普通用户 token 不返回。</li>
     * </ul>
     */
    private List<String> authorities;

    public static IntrospectResponse inactive() {
        IntrospectResponse r = new IntrospectResponse();
        r.active = false;
        return r;
    }

    public static IntrospectResponse active(OAuthAccessToken at) {
        IntrospectResponse r = new IntrospectResponse();
        r.active = true;
        r.clientId = at.clientId();
        r.subjectType = at.subjectType();
        r.userId = at.userId();
        r.scope = at.scopes() == null ? null : String.join(" ", at.scopes());
        Instant exp = at.expiresAt();
        r.exp = exp == null ? 0 : exp.getEpochSecond();
        return r;
    }

    /**
     * Sa-Token OAuth2 的 access_token 自省。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>password / authorization_code：loginId 为用户ID</li>
     *   <li>scope：Sa-Token 内部是 CSV，这里对外按 OAuth2 习惯返回空格分隔</li>
     * </ul>
     */
    public static IntrospectResponse active(AccessTokenModel at) {
        IntrospectResponse r = new IntrospectResponse();
        r.active = true;
        r.clientId = at.clientId;
        r.subjectType = at.loginId == null ? "client" : "user";
        r.userId = at.loginId == null ? null : String.valueOf(at.loginId);
        r.scope = at.scope == null ? null : at.scope.replace(",", " ").trim();
        r.exp = at.expiresTime <= 0 ? 0 : at.expiresTime / 1000;
        return r;
    }

    /**
     * Sa-Token OAuth2 的 client_token（client_credentials）自省。
     *
     * <p>注意：这里将 client_token 统一当作 OAuth2 的 access_token 来校验，因此返回的 sub 为空。</p>
     */
    public static IntrospectResponse active(ClientTokenModel ct) {
        IntrospectResponse r = new IntrospectResponse();
        r.active = true;
        r.clientId = ct.clientId;
        r.subjectType = "client";
        r.userId = null;
        r.scope = ct.scope == null ? null : ct.scope.replace(",", " ").trim();
        r.exp = ct.expiresTime <= 0 ? 0 : ct.expiresTime / 1000;
        return r;
    }
}
