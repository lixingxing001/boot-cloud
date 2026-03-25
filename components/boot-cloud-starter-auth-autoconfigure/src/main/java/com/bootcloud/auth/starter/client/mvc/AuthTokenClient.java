package com.bootcloud.auth.starter.client.mvc;

import com.bootcloud.auth.starter.core.AuthClientConfig;
import com.bootcloud.auth.starter.util.BasicAuthUtil;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

/**
 * MVC 场景下调用 boot-cloud-auth 的 token 端点封装（RestTemplate）。
 *
 * <ul>
 *   <li>该 client 返回 {@code ResponseEntity<String>}，便于 BFF 原样透传上游响应。</li>
 *   <li>如需强类型，可在调用方自行把 body 反序列化为 DTO。</li>
 * </ul>
 */
public class AuthTokenClient {

    private final RestTemplate restTemplate;
    private final AuthClientConfig config;

    public AuthTokenClient(RestTemplate restTemplate, AuthClientConfig config) {
        this.restTemplate = restTemplate;
        this.config = config;
    }

    public ResponseEntity<String> passwordToken(String tenantId, String username, String password, String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", config.getClientId());
        if (!config.isUseBasicAuth()) {
            form.add("client_secret", config.getClientSecret());
        }
        form.add("username", username);
        form.add("password", password);
        if (StringUtils.hasText(scope)) {
            form.add("scope", scope);
        }
        return postForm(tenantId, form);
    }

    public ResponseEntity<String> refreshToken(String tenantId, String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", config.getClientId());
        if (!config.isUseBasicAuth()) {
            form.add("client_secret", config.getClientSecret());
        }
        form.add("refresh_token", refreshToken);
        return postForm(tenantId, form);
    }

    /**
     * authorization_code -> token。
     */
    public ResponseEntity<String> authorizationCodeToken(String tenantId, String code, String redirectUri, String codeVerifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", config.getClientId());
        if (!config.isUseBasicAuth()) {
            form.add("client_secret", config.getClientSecret());
        }
        form.add("code", code);
        if (StringUtils.hasText(redirectUri)) {
            form.add("redirect_uri", redirectUri);
        }
        if (StringUtils.hasText(codeVerifier)) {
            form.add("code_verifier", codeVerifier);
        }
        return postForm(tenantId, form);
    }

    private ResponseEntity<String> postForm(String tenantId, MultiValueMap<String, String> form) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (StringUtils.hasText(tenantId)) {
            headers.set(config.getTenantHeaderName(), tenantId.trim());
        }
        if (config.isUseBasicAuth() && StringUtils.hasText(config.getClientId())) {
            headers.set(HttpHeaders.AUTHORIZATION, BasicAuthUtil.basic(config.getClientId(), config.getClientSecret()));
        }
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);
        try {
            return restTemplate.postForEntity(config.tokenUrl(), entity, String.class);
        } catch (HttpStatusCodeException e) {
            MediaType ct = e.getResponseHeaders() != null ? e.getResponseHeaders().getContentType() : null;
            return ResponseEntity.status(e.getStatusCode())
                    .contentType(ct != null ? ct : MediaType.APPLICATION_JSON)
                    .body(e.getResponseBodyAsString());
        }
    }
}
