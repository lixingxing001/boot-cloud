package com.bootcloud.base.controller.internal.admin;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.bootcloud.base.core.oauth.OAuthClientAdminService;
import com.bootcloud.base.core.oauth.OAuthClientAdminService.ResetSecretResult;
import com.bootcloud.base.infra.mybatis.entity.OAuthClientEntity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 内部管理接口：OAuth Client 管理（boot_cloud_oauth_client）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>路径在 {@code /internal/admin/**}，并由拦截器要求携带内部密钥头（见 {@code boot.cloud.internal-auth.*}）。</li>
 *   <li>该接口用于“可运营化”：不再手工改 SQL 就能新增 client / 重置 secret / 启停 client。</li>
 * </ul>
 */
@Validated
@RestController
@RequestMapping("/internal/admin/oauth-clients")
public class OAuthClientAdminController {

    private static final Logger log = LoggerFactory.getLogger(OAuthClientAdminController.class);

    private final OAuthClientAdminService adminService;

    public OAuthClientAdminController(OAuthClientAdminService adminService) {
        this.adminService = adminService;
    }

    /**
     * 分页查询 client（tenantId=0 表示系统级）。
     */
    @GetMapping
    public IPage<OAuthClientView> page(
            HttpServletRequest request,
            @RequestParam(value = "tenantId", required = false) Long tenantId,
            @RequestParam(value = "clientIdLike", required = false) String clientIdLike,
            @RequestParam(value = "status", required = false) Integer status,
            @RequestParam(value = "page", defaultValue = "1") @Min(1) int page,
            @RequestParam(value = "size", defaultValue = "20") @Min(1) @Max(200) int size
    ) {
        long tid = resolveTenantForRead(request, tenantId);
        IPage<OAuthClientEntity> p = adminService.page(tid, clientIdLike, status, page, size);
        // 不返回 client_secret（敏感）
        return p.convert(OAuthClientView::from);
    }

    /**
     * 查询单个 client（不返回 client_secret）。
     */
    @GetMapping("/{id}")
    public OAuthClientView get(HttpServletRequest request,
                               @PathVariable("id") long id,
                               @RequestParam(value = "tenantId", required = false) Long tenantId) {
        long tid = resolveTenantForRead(request, tenantId);
        OAuthClientEntity e = adminService.get(tid, id);
        if (e == null) {
            throw new IllegalArgumentException("client not found");
        }
        return OAuthClientView.from(e);
    }

    /**
     * 创建 client（client_secret 传明文，服务端存 BCrypt hash）。
     */
    @PostMapping
    public OAuthClientView create(HttpServletRequest request, @Valid @RequestBody CreateRequest body) {
        OAuthClientAdminService.CreateCommand cmd = new OAuthClientAdminService.CreateCommand();
        cmd.tenantId = resolveTenantForWrite(request, body.tenantId);
        cmd.clientId = body.clientId;
        cmd.clientSecretPlain = body.clientSecret;
        cmd.clientName = body.clientName;
        cmd.grantTypes = body.grantTypes;
        cmd.scopes = body.scopes;
        cmd.redirectUris = body.redirectUris;
        cmd.accessTokenTtlSeconds = body.accessTokenTtlSeconds;
        cmd.refreshTokenTtlSeconds = body.refreshTokenTtlSeconds;
        cmd.allowRefreshToken = body.allowRefreshToken;
        cmd.status = body.status == null ? 1 : body.status;
        cmd.remark = body.remark;

        OAuthClientEntity e = adminService.create(cmd);
        log.info("内部管理：创建 client 成功，tenantId={}, clientId={}", cmd.tenantId, e.getClientId());
        return OAuthClientView.from(e);
    }

    /**
     * 更新 client 基础信息（不更新 secret）。
     */
    @PutMapping("/{id}")
    public OAuthClientView update(HttpServletRequest request,
                                  @PathVariable("id") long id,
                                  @Valid @RequestBody UpdateRequest body) {
        OAuthClientAdminService.UpdateCommand cmd = new OAuthClientAdminService.UpdateCommand();
        cmd.tenantId = resolveTenantForWrite(request, body.tenantId);
        cmd.id = id;
        cmd.clientName = body.clientName;
        cmd.grantTypes = body.grantTypes;
        cmd.scopes = body.scopes;
        cmd.redirectUris = body.redirectUris;
        cmd.accessTokenTtlSeconds = body.accessTokenTtlSeconds;
        cmd.refreshTokenTtlSeconds = body.refreshTokenTtlSeconds;
        cmd.allowRefreshToken = body.allowRefreshToken;
        cmd.status = body.status;
        cmd.remark = body.remark;

        OAuthClientEntity e = adminService.update(cmd);
        return OAuthClientView.from(e);
    }

    /**
     * 重置 client_secret（可传指定明文，也可不传让服务端生成随机值）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>返回的 clientSecret 明文只会出现一次；调用方应自行保存。</li>
     *   <li>如果要创建 public client（SPA），可把 secret 设为 <code>{public}</code>。</li>
     * </ul>
     */
    @PostMapping("/{id}/reset-secret")
    public ResetSecretResult resetSecret(HttpServletRequest request,
                                         @PathVariable("id") long id,
                                         @Valid @RequestBody ResetSecretRequest body) {
        long tid = resolveTenantForWrite(request, body.tenantId);
        return adminService.resetSecret(tid, id, body.clientSecret);
    }

    /**
     * 硬删除 client（物理删除）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该接口属于高危管理操作，仅允许内部调用，并且必须带内部密钥头。</li>
     *   <li>建议先通过 update 把 status 置为 0（禁用），确认无影响后再执行删除。</li>
     * </ul>
     */
    @DeleteMapping("/{id}")
    public DeleteResult delete(HttpServletRequest request,
                               @PathVariable("id") long id,
                               @RequestParam(value = "tenantId", required = false) Long tenantId) {
        long tid = resolveTenantForWrite(request, tenantId);
        adminService.delete(tid, id);
        log.info("内部管理：删除 client 成功，tenantId={}, id={}", tid, id);
        return new DeleteResult(true);
    }

    /**
     * 租户归属收敛策略。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>优先使用可信请求头 X-Tenant-Id。</li>
     *   <li>若头与参数同时存在且不一致，直接拒绝，避免跨租户误写。</li>
     *   <li>写操作若头和参数都缺失，直接拒绝，避免误写入默认租户。</li>
     * </ul>
     */
    private static long resolveTenantForWrite(HttpServletRequest request, Long requestedTenantId) {
        if (requestedTenantId != null && requestedTenantId == 0L) {
            return 0L;
        }
        Long fromHeader = parseLongPositive(request == null ? null : request.getHeader("X-Tenant-Id"));
        if (fromHeader != null) {
        if (requestedTenantId != null && requestedTenantId >= 0 && !fromHeader.equals(requestedTenantId)) {
                log.warn("内部管理写租户不一致：headerTenantId={}, requestedTenantId={}, path={}",
                        fromHeader, requestedTenantId, request == null ? "" : request.getRequestURI());
                throw new IllegalArgumentException("tenantId mismatch between header and request");
            }
            if (log.isDebugEnabled()) {
                log.debug("内部管理写租户来源=header，tenantId={}, path={}", fromHeader, request == null ? "" : request.getRequestURI());
            }
            return fromHeader;
        }
        if (requestedTenantId != null && requestedTenantId >= 0) {
            if (log.isDebugEnabled()) {
                log.debug("内部管理写租户来源=request，tenantId={}, path={}", requestedTenantId, request == null ? "" : request.getRequestURI());
            }
            return requestedTenantId;
        }
        log.warn("内部管理写租户缺失：headerTenantId={}, requestedTenantId={}, path={}",
                null, requestedTenantId, request == null ? "" : request.getRequestURI());
        throw new IllegalArgumentException("tenantId is required for write");
    }

    private static long resolveTenantForRead(HttpServletRequest request, Long requestedTenantId) {
        if (requestedTenantId != null && requestedTenantId == 0L) {
            return 0L;
        }
        Long fromHeader = parseLongPositive(request == null ? null : request.getHeader("X-Tenant-Id"));
        if (fromHeader != null) {
            return fromHeader;
        }
        if (requestedTenantId != null && requestedTenantId >= 0) {
            return requestedTenantId;
        }
        return 1L;
    }

    private static Long parseLongPositive(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        try {
            long v = Long.parseLong(raw.trim());
            return v >= 0 ? v : null;
        } catch (Exception e) {
            return null;
        }
    }

    @Validated
    public static class CreateRequest {
        public Long tenantId;

        @NotBlank
        public String clientId;

        @NotBlank
        public String clientSecret;

        public String clientName;

        /**
         * CSV：authorization_code,password,client_credentials,refresh_token
         */
        @NotBlank
        public String grantTypes;

        public String scopes;

        /**
         * redirect_uri 列表（推荐数组，服务端会存 JSON 数组字符串）
         */
        public List<String> redirectUris;

        public Integer accessTokenTtlSeconds;

        public Integer refreshTokenTtlSeconds;

        public Integer allowRefreshToken;

        public Integer status;

        public String remark;
    }

    @Validated
    public static class UpdateRequest {
        public Long tenantId;
        public String clientName;
        public String grantTypes;
        public String scopes;
        public List<String> redirectUris;
        public Integer accessTokenTtlSeconds;
        public Integer refreshTokenTtlSeconds;
        public Integer allowRefreshToken;
        public Integer status;
        public String remark;
    }

    @Validated
    public static class ResetSecretRequest {
        public Long tenantId;
        /**
         * 可选：指定新 secret；为空则自动生成。
         */
        public String clientSecret;
    }

    /**
     * 对外返回视图：不包含 client_secret（敏感）。
     */
    public record OAuthClientView(
            long id,
            long tenantId,
            String scopeType,
            String clientId,
            String clientName,
            String grantTypes,
            String scopes,
            String redirectUris,
            Integer accessTokenTtlSeconds,
            Integer refreshTokenTtlSeconds,
            Integer allowRefreshToken,
            Integer status,
            String remark
    ) {
        public static OAuthClientView from(OAuthClientEntity e) {
            return new OAuthClientView(
                    e.getId() == null ? 0 : e.getId(),
                    e.getTenantId() == null ? 0 : e.getTenantId(),
                    e.getScopeType(),
                    e.getClientId(),
                    e.getClientName(),
                    e.getGrantTypes(),
                    e.getScopes(),
                    e.getRedirectUris(),
                    e.getAccessTokenTtlSeconds(),
                    e.getRefreshTokenTtlSeconds(),
                    e.getAllowRefreshToken(),
                    e.getStatus(),
                    e.getRemark()
            );
        }
    }

    public record DeleteResult(boolean deleted) {
    }
}
