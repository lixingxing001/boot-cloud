package com.bootcloud.auth.infra.satoken.oauth2;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bootcloud.auth.config.AuthServerProperties;
import com.bootcloud.auth.core.tenant.TenantContext;
import com.bootcloud.auth.infra.mybatis.entity.OAuthClientEntity;
import com.bootcloud.auth.infra.mybatis.mapper.OAuthClientMapper;
import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.oauth2.exception.SaOAuth2Exception;
import cn.dev33.satoken.oauth2.model.CodeModel;
import cn.dev33.satoken.oauth2.model.RefreshTokenModel;
import cn.dev33.satoken.oauth2.model.SaClientModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Sa-Token OAuth2 的自定义模板：Client 从 DB 读取，并做多租户隔离。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>Sa-Token OAuth2 默认示例通常是“内存 client + 明文 secret”。</li>
 *   <li>本项目 client 需要从 {@code boot_cloud_oauth_client} 动态读取，并且 client_secret 生产建议存 BCrypt。</li>
 *   <li>因此这里覆写：client 查询、secret 校验（支持 BCrypt）、以及 Redis Key 拼接（加入 tenantId）。</li>
 * </ul>
 *
 * <p>为什么不直接复用 DbClientRegistry？</p>
 * <ul>
 *   <li>Sa-Token OAuth2 使用 {@link SaClientModel}，而旧的自研 OAuth 使用 {@code OAuthClient}。</li>
 *   <li>两者字段含义相近但不完全一致，直接适配会导致“边界逻辑”分散在多处，不利于后期维护。</li>
 * </ul>
 */
public class SaOAuth2Template extends cn.dev33.satoken.oauth2.logic.SaOAuth2Template {

    private static final Logger log = LoggerFactory.getLogger(SaOAuth2Template.class);

    /**
     * Sa-Token OAuth2 内置的 Key 前缀是固定的。这里换成 evm 前缀并加入 tenantId，避免未来多租户时冲突。
     *
     * <p>注意：该前缀变更会影响 token 的存储结构；如果线上已发放 token，切换后无法互认（需要灰度/强制重新登录）。</p>
     */
    private static final String KEY_PREFIX = "bootcloud:oauth2:";

    /**
     * client 缓存结构版本。
     *
     * <p>说明：后续如果缓存字段结构有变更，可以升级版本号，避免新旧结构互相污染。</p>
     */
    private static final String CLIENT_CACHE_VERSION = "v4";

    private final OAuthClientMapper clientMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthServerProperties properties;
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;

    public SaOAuth2Template(
            OAuthClientMapper clientMapper,
            PasswordEncoder passwordEncoder,
            AuthServerProperties properties,
            StringRedisTemplate redis,
            ObjectMapper mapper
    ) {
        this.clientMapper = clientMapper;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
        this.redis = redis;
        this.mapper = mapper;
    }

    @Override
    public SaClientModel getClientModel(String clientId) {
        long tenantId = TenantContext.getTenantIdOrDefault();
        // 说明：
        // tenant_id=0 现在用于系统级 OAuth client，会被后台 BFF、自省、网关等基础设施链路使用。
        // 这里仅拦截负数租户，避免把系统级 client 误判成“无效 client_id”。
        if (!StringUtils.hasText(clientId) || tenantId < 0) {
            return null;
        }

        // 说明：client 信息缓存
        // 用途：降低 /oauth/check_token 自省时的 DB 压力（每次自省都会校验 client_id/client_secret）
        // 策略：短 TTL 缓存，缓存失败自动降级查库
        CacheLookupResult cached = getClientModelFromCache(tenantId, clientId);
        if (cached.hit && cached.negative) {
            return null;
        }
        if (cached.model != null) {
            return cached.model;
        }

        ClientLookupResult lookup = findClientEntity(tenantId, clientId);
        OAuthClientEntity e = lookup.entity();
        if (e == null) {
            putNegativeClientModelToCache(tenantId, clientId);
            return null;
        }
        if (log.isDebugEnabled()) {
            log.debug("oauth2 client db hit: tenantId={}, clientId={}, resolvedScopeType={}, storedTenantId={}",
                    tenantId, clientId, lookup.resolvedScopeType(), e.getTenantId());
        }

        // grant_types: authorization_code,password,client_credentials,refresh_token
        Set<String> grantTypes = splitCsvLower(e.getGrantTypes());
        String contractScope = normalizeScopeCsv(e.getScopes());

        SaClientModel model = new SaClientModel();
        model.setClientId(e.getClientId());
        model.setClientSecret(e.getClientSecret());
        model.setContractScope(contractScope);
        model.setAllowUrl(String.join(",", parseRedirectUris(e.getRedirectUris())));

        // Sa-Token OAuth2 的开关粒度是 isCode/isPassword/isClient/isImplicit
        model.setIsCode(grantTypes.contains("authorization_code"));
        model.setIsPassword(grantTypes.contains("password"));
        model.setIsClient(grantTypes.contains("client_credentials"));
        model.setIsImplicit(false);

        // 当前阶段不启用“自动模式”（自动模式会绕过部分开关判断，不建议默认开启）
        model.setIsAutoMode(false);

        // refresh token 策略：当前策略可配置“是否复用 refresh_token”
        // - reuseRefreshToken=true  -> isNewRefresh=false （刷新时不轮换 refresh_token）
        // - reuseRefreshToken=false -> isNewRefresh=true  （刷新时轮换 refresh_token）
        model.setIsNewRefresh(!properties.isReuseRefreshToken());

        long at = e.getAccessTokenTtlSeconds() == null ? 7200L : Math.max(e.getAccessTokenTtlSeconds(), 1);
        long rt = e.getRefreshTokenTtlSeconds() == null ? 2592000L : Math.max(e.getRefreshTokenTtlSeconds(), 1);
        model.setAccessTokenTimeout(at);
        model.setRefreshTokenTimeout(rt);

        // client_credentials 走的是 Sa-Token 的 client_token，timeout 独立配置
        model.setClientTokenTimeout(at);
        model.setPastClientTokenTimeout(0L);

        putClientModelToCache(tenantId, clientId, model);
        return model;
    }

    /**
     * 说明：
     * 当前 client 查询采用“双层作用域”策略。
     * 1. 先查租户级 client，保留后续按租户覆盖 OAuth 参数的能力。
     * 2. 若未命中，则回退到系统级 client，保证网关、自省、后台 BFF 等基础设施不被默认租户切换拖动。
     */
    private ClientLookupResult findClientEntity(long tenantId, String clientId) {
        // 说明：
        // 当当前上下文已经是 tenant_id=0 时，直接走系统级查询，避免先查 tenant 作用域再回退时产生歧义。
        if (tenantId == OAuthClientEntity.SYSTEM_TENANT_ID) {
            OAuthClientEntity systemClient = clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                    .eq(OAuthClientEntity::getTenantId, OAuthClientEntity.SYSTEM_TENANT_ID)
                    .eq(OAuthClientEntity::getScopeType, OAuthClientEntity.SCOPE_TYPE_SYSTEM)
                    .eq(OAuthClientEntity::getClientId, clientId)
                    .eq(OAuthClientEntity::getStatus, 1)
                    .last("LIMIT 1"));
            if (systemClient != null) {
                if (log.isDebugEnabled()) {
                    log.debug("oauth2 client 命中系统级查询：tenantId={}, clientId={}, scopeType={}",
                            tenantId, clientId, OAuthClientEntity.SCOPE_TYPE_SYSTEM);
                }
                return ClientLookupResult.of(systemClient, OAuthClientEntity.SCOPE_TYPE_SYSTEM);
            }
            return ClientLookupResult.empty();
        }

        // 说明：
        // 对于“服务基础设施 client”，优先命中 SYSTEM 作用域。
        // 原因：这类 client 代表的是服务自身身份，不应随着默认租户切换而被租户级同名副本抢走。
        // 兼容策略：若 SYSTEM 未配置，再回退租户级，避免迁移窗口直接中断现网。
        if (preferSystemScope(clientId)) {
            OAuthClientEntity preferredSystemClient = clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                    .eq(OAuthClientEntity::getTenantId, OAuthClientEntity.SYSTEM_TENANT_ID)
                    .eq(OAuthClientEntity::getScopeType, OAuthClientEntity.SCOPE_TYPE_SYSTEM)
                    .eq(OAuthClientEntity::getClientId, clientId)
                    .eq(OAuthClientEntity::getStatus, 1)
                    .last("LIMIT 1"));
            if (preferredSystemClient != null) {
                if (log.isDebugEnabled()) {
                    log.debug("oauth2 client 命中系统优先策略：requestTenantId={}, clientId={}, storedTenantId={}",
                            tenantId, clientId, preferredSystemClient.getTenantId());
                }
                return ClientLookupResult.of(preferredSystemClient, OAuthClientEntity.SCOPE_TYPE_SYSTEM);
            }
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client 系统优先策略未命中 SYSTEM，回退租户级查询：requestTenantId={}, clientId={}",
                        tenantId, clientId);
            }
        }

        OAuthClientEntity tenantClient = clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, tenantId)
                .eq(OAuthClientEntity::getClientId, clientId)
                .eq(OAuthClientEntity::getStatus, 1)
                .and(w -> w.isNull(OAuthClientEntity::getScopeType)
                        .or()
                        .eq(OAuthClientEntity::getScopeType, OAuthClientEntity.SCOPE_TYPE_TENANT))
                .last("LIMIT 1"));
        if (tenantClient != null) {
            return ClientLookupResult.of(tenantClient, OAuthClientEntity.SCOPE_TYPE_TENANT);
        }

        OAuthClientEntity systemClient = clientMapper.selectOne(new LambdaQueryWrapper<OAuthClientEntity>()
                .eq(OAuthClientEntity::getTenantId, OAuthClientEntity.SYSTEM_TENANT_ID)
                .eq(OAuthClientEntity::getScopeType, OAuthClientEntity.SCOPE_TYPE_SYSTEM)
                .eq(OAuthClientEntity::getClientId, clientId)
                .eq(OAuthClientEntity::getStatus, 1)
                .last("LIMIT 1"));
        if (systemClient != null) {
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client 命中系统级 fallback：requestTenantId={}, clientId={}, storedTenantId={}",
                        tenantId, clientId, systemClient.getTenantId());
            }
            return ClientLookupResult.of(systemClient, OAuthClientEntity.SCOPE_TYPE_SYSTEM);
        }
        return ClientLookupResult.empty();
    }

    /**
     * 判断当前 client 是否应该优先命中 SYSTEM 作用域。
     */
    private boolean preferSystemScope(String clientId) {
        if (!StringUtils.hasText(clientId) || properties == null) {
            return false;
        }
        AuthServerProperties.SystemClientPreferenceConfig cfg = properties.effectiveSystemClientPreference();
        if (cfg == null || !cfg.isEnabled() || cfg.getClientIds() == null || cfg.getClientIds().isEmpty()) {
            return false;
        }
        String normalizedClientId = clientId.trim().toLowerCase(Locale.ROOT);
        return cfg.getClientIds().stream()
                .filter(StringUtils::hasText)
                .map(v -> v.trim().toLowerCase(Locale.ROOT))
                .anyMatch(normalizedClientId::equals);
    }

    private CacheLookupResult getClientModelFromCache(long tenantId, String clientId) {
        if (!isClientCacheEnabled() || redis == null || mapper == null) {
            return CacheLookupResult.noHit();
        }
        String key = splicingClientModelCacheKey(tenantId, clientId);
        try {
            String cached = redis.opsForValue().get(key);
            if (!StringUtils.hasText(cached)) {
                if (log.isDebugEnabled()) {
                    log.debug("oauth2 client cache miss: tenantId={}, clientId={}", tenantId, clientId);
                }
                return CacheLookupResult.noHit();
            }
            CachedClientModel v = mapper.readValue(cached, CachedClientModel.class);
            if (v != null && v.isPresent != null && !v.isPresent) {
                if (log.isDebugEnabled()) {
                    log.debug("oauth2 client negative cache hit: tenantId={}, clientId={}", tenantId, clientId);
                }
                return CacheLookupResult.negativeHit();
            }
            SaClientModel m = v == null ? null : v.toSaClientModel();
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client cache hit: tenantId={}, clientId={}", tenantId, clientId);
            }
            return CacheLookupResult.modelHit(m);
        } catch (Exception e) {
            // 说明：缓存异常不影响主流程，降级查库即可
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client cache read failed, fallback to db: tenantId={}, clientId={}, err={}",
                        tenantId, clientId, e.getMessage());
            }
            return CacheLookupResult.noHit();
        }
    }

    private void putClientModelToCache(long tenantId, String clientId, SaClientModel model) {
        if (!isClientCacheEnabled() || redis == null || mapper == null || model == null) {
            return;
        }
        Duration ttl = clientCacheTtl();
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        String key = splicingClientModelCacheKey(tenantId, clientId);
        try {
            CachedClientModel v = CachedClientModel.from(model);
            redis.opsForValue().set(key, mapper.writeValueAsString(v), ttl);
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client cache set: tenantId={}, clientId={}, ttlSeconds={}",
                        tenantId, clientId, ttl.toSeconds());
            }
        } catch (Exception e) {
            // 说明：写缓存失败不影响主流程
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client cache write failed: tenantId={}, clientId={}, err={}",
                        tenantId, clientId, e.getMessage());
            }
        }
    }

    private void putNegativeClientModelToCache(long tenantId, String clientId) {
        if (!isClientCacheEnabled() || !isClientNegativeCacheEnabled() || redis == null || mapper == null) {
            return;
        }
        Duration ttl = clientNegativeCacheTtl();
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        String key = splicingClientModelCacheKey(tenantId, clientId);
        try {
            CachedClientModel v = CachedClientModel.negative(clientId);
            redis.opsForValue().set(key, mapper.writeValueAsString(v), ttl);
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client negative cache set: tenantId={}, clientId={}, ttlSeconds={}",
                        tenantId, clientId, ttl.toSeconds());
            }
        } catch (Exception e) {
            // 说明：写缓存失败不影响主流程
            if (log.isDebugEnabled()) {
                log.debug("oauth2 client negative cache write failed: tenantId={}, clientId={}, err={}",
                        tenantId, clientId, e.getMessage());
            }
        }
    }

    private boolean isClientCacheEnabled() {
        if (properties == null || properties.getClientCache() == null) {
            return false;
        }
        return properties.getClientCache().isEnabled();
    }

    private boolean isClientNegativeCacheEnabled() {
        if (properties == null || properties.getClientCache() == null) {
            return false;
        }
        return properties.getClientCache().isNegativeEnabled();
    }

    private Duration clientCacheTtl() {
        if (properties == null || properties.getClientCache() == null) {
            return Duration.ZERO;
        }
        long seconds = properties.getClientCache().getTtlSeconds();
        seconds = Math.max(5, seconds);
        return Duration.ofSeconds(seconds);
    }

    private Duration clientNegativeCacheTtl() {
        if (properties == null || properties.getClientCache() == null) {
            return Duration.ZERO;
        }
        long seconds = properties.getClientCache().getNegativeTtlSeconds();
        seconds = Math.max(1, seconds);
        return Duration.ofSeconds(seconds);
    }

    private String splicingClientModelCacheKey(long tenantId, String clientId) {
        // 说明：key 结构与 access_token 等保持同一前缀，并加入 tenantId 做隔离。
        return KEY_PREFIX + tenantId + ":client:" + CLIENT_CACHE_VERSION + ":" + clientId;
    }

    /**
     * client 缓存结构。
     *
     * <p>说明：只缓存自省校验所需的最小字段。</p>
     */
    public static class CachedClientModel {
        /**
         * 是否存在。
         *
         * <p>说明：</p>
         * <ul>
         *   <li>true：正常 client 缓存</li>
         *   <li>false：空结果短缓存（negative cache）</li>
         * </ul>
         */
        public Boolean isPresent;
        public String clientId;
        public String clientSecret;
        public String contractScope;
        public String allowUrl;
        public boolean isCode;
        public boolean isPassword;
        public boolean isClient;
        public boolean isImplicit;
        public Long accessTokenTimeout;
        public Long refreshTokenTimeout;
        public Long clientTokenTimeout;
        public Long pastClientTokenTimeout;
        public Boolean isNewRefresh;

        public static CachedClientModel from(SaClientModel m) {
            CachedClientModel v = new CachedClientModel();
            v.isPresent = true;
            v.clientId = m.getClientId();
            v.clientSecret = m.getClientSecret();
            v.contractScope = m.getContractScope();
            v.allowUrl = m.getAllowUrl();
            v.isCode = m.getIsCode();
            v.isPassword = m.getIsPassword();
            v.isClient = m.getIsClient();
            v.isImplicit = m.getIsImplicit();
            v.accessTokenTimeout = m.getAccessTokenTimeout();
            v.refreshTokenTimeout = m.getRefreshTokenTimeout();
            v.clientTokenTimeout = m.getClientTokenTimeout();
            v.pastClientTokenTimeout = m.getPastClientTokenTimeout();
            v.isNewRefresh = m.getIsNewRefresh();
            return v;
        }

        public static CachedClientModel negative(String clientId) {
            CachedClientModel v = new CachedClientModel();
            v.isPresent = false;
            v.clientId = clientId;
            return v;
        }

        public SaClientModel toSaClientModel() {
            if (!StringUtils.hasText(clientId)) {
                return null;
            }
            SaClientModel m = new SaClientModel();
            m.setClientId(clientId);
            m.setClientSecret(clientSecret);
            m.setContractScope(contractScope);
            m.setAllowUrl(allowUrl);
            m.setIsCode(isCode);
            m.setIsPassword(isPassword);
            m.setIsClient(isClient);
            m.setIsImplicit(isImplicit);
            if (accessTokenTimeout != null) m.setAccessTokenTimeout(accessTokenTimeout);
            if (refreshTokenTimeout != null) m.setRefreshTokenTimeout(refreshTokenTimeout);
            if (clientTokenTimeout != null) m.setClientTokenTimeout(clientTokenTimeout);
            if (pastClientTokenTimeout != null) m.setPastClientTokenTimeout(pastClientTokenTimeout);
            if (isNewRefresh != null) m.setIsNewRefresh(isNewRefresh);
            return m;
        }
    }

    private static class CacheLookupResult {
        final boolean hit;
        final boolean negative;
        final SaClientModel model;

        private CacheLookupResult(boolean hit, boolean negative, SaClientModel model) {
            this.hit = hit;
            this.negative = negative;
            this.model = model;
        }

        static CacheLookupResult noHit() {
            return new CacheLookupResult(false, false, null);
        }

        static CacheLookupResult negativeHit() {
            return new CacheLookupResult(true, true, null);
        }

        static CacheLookupResult modelHit(SaClientModel model) {
            return new CacheLookupResult(true, false, model);
        }
    }

    private record ClientLookupResult(OAuthClientEntity entity, String resolvedScopeType) {
        private static ClientLookupResult empty() {
            return new ClientLookupResult(null, "");
        }

        private static ClientLookupResult of(OAuthClientEntity entity, String resolvedScopeType) {
            return new ClientLookupResult(entity, resolvedScopeType);
        }
    }

    /**
     * 覆写原因：Sa-Token OAuth2 默认使用 {@code String.equals} 校验 client_secret，
     * 但本项目 client_secret 建议存 BCrypt 哈希。
     */
    @Override
    public SaClientModel checkClientSecret(String clientId, String clientSecret) {
        SaClientModel model = checkClientModel(clientId);
        String stored = model.clientSecret;

        boolean notMatch = (stored == null) || !matchSecret(stored, clientSecret);
        SaOAuth2Exception.throwBy(
                notMatch,
                "无效client_secret:" + clientSecret,
                30115
        );
        return model;
    }

    /**
     * 覆写原因同 {@link #checkClientSecret(String, String)}。
     *
     * <p>同时：Sa-Token 的 scope 分隔符默认是逗号（CSV）。为了兼容 OAuth2 标准的“空格分隔”，
     * 建议在 controller/request-wrapper 处统一把 scope 规范化为 CSV。</p>
     */
    @Override
    public CodeModel checkGainTokenParam(String code, String clientId, String clientSecret, String redirectUri) {
        CodeModel cm = getCode(code);
        SaOAuth2Exception.throwBy(
                cm == null,
                "无效code:" + code,
                30117
        );
        SaOAuth2Exception.throwBy(
                !cm.clientId.equals(clientId),
                "无效client_id:" + clientId,
                30118
        );

        String stored = checkClientModel(clientId).clientSecret;
        SaOAuth2Exception.throwBy(
                (stored == null) || !matchSecret(stored, clientSecret),
                "无效client_secret:" + clientSecret,
                30119
        );

        if (!cn.dev33.satoken.util.SaFoxUtil.isEmpty(redirectUri)) {
            SaOAuth2Exception.throwBy(
                    !redirectUri.equals(cm.redirectUri),
                    "无效redirect_uri:" + redirectUri,
                    30120
            );
        }

        return cm;
    }

    /**
     * 覆写原因：refresh_token 的参数校验同样需要支持 BCrypt 的 client_secret。
     */
    @Override
    public RefreshTokenModel checkRefreshTokenParam(String clientId, String clientSecret, String refreshToken) {
        RefreshTokenModel rt = getRefreshToken(refreshToken);
        SaOAuth2Exception.throwBy(
                rt == null,
                "无效refresh_token:" + refreshToken,
                30121
        );
        SaOAuth2Exception.throwBy(
                !rt.clientId.equals(clientId),
                "无效client_id:" + clientId,
                30122
        );

        String stored = checkClientModel(clientId).clientSecret;
        SaOAuth2Exception.throwBy(
                (stored == null) || !matchSecret(stored, clientSecret),
                "无效client_secret:" + clientSecret,
                30123
        );
        return rt;
    }

    @Override
    public String splicingCodeSaveKey(String code) {
        return KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":code:" + code;
    }

    @Override
    public String splicingCodeIndexKey(String clientId, Object loginId) {
        String base = KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":code-idx:" + clientId + ":" + loginId;
        return appendDeviceIfNeeded(base, clientId);
    }

    @Override
    public String splicingAccessTokenSaveKey(String accessToken) {
        return KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":at:" + accessToken;
    }

    @Override
    public String splicingAccessTokenIndexKey(String clientId, Object loginId) {
        String base = KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":at-idx:" + clientId + ":" + loginId;
        return appendDeviceIfNeeded(base, clientId);
    }

    @Override
    public String splicingRefreshTokenSaveKey(String refreshToken) {
        return KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":rt:" + refreshToken;
    }

    @Override
    public String splicingRefreshTokenIndexKey(String clientId, Object loginId) {
        String base = KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":rt-idx:" + clientId + ":" + loginId;
        return appendDeviceIfNeeded(base, clientId);
    }

    /**
     * 获取指定 deviceId 下的 access_token 值（从 index key 读取）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>用于“登录设备管理”的远程登出。</li>
     *   <li>注意：该方法不依赖当前 HTTP 请求上下文，显式传入 deviceId。</li>
     * </ul>
     */
    public String getAccessTokenValueByDevice(String clientId, Object loginId, String rawDeviceId) {
        String key = splicingAccessTokenIndexKeyByDevice(clientId, loginId, rawDeviceId);
        if (!StringUtils.hasText(key)) {
            return null;
        }
        try {
            return redis.opsForValue().get(key);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取指定 deviceId 下的 refresh_token 值（从 index key 读取）。
     */
    public String getRefreshTokenValueByDevice(String clientId, Object loginId, String rawDeviceId) {
        String key = splicingRefreshTokenIndexKeyByDevice(clientId, loginId, rawDeviceId);
        if (!StringUtils.hasText(key)) {
            return null;
        }
        try {
            return redis.opsForValue().get(key);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 删除指定 deviceId 的 token index key（仅删除 index，不删除 token save key）。
     *
     * <p>说明：真正的 token save key 删除由 revokeAccessToken/deleteRefreshToken 完成。</p>
     */
    public void deleteTokenIndexByDevice(String clientId, Object loginId, String rawDeviceId) {
        try {
            String atIdx = splicingAccessTokenIndexKeyByDevice(clientId, loginId, rawDeviceId);
            String rtIdx = splicingRefreshTokenIndexKeyByDevice(clientId, loginId, rawDeviceId);
            if (StringUtils.hasText(atIdx)) {
                redis.delete(atIdx);
            }
            if (StringUtils.hasText(rtIdx)) {
                redis.delete(rtIdx);
            }
        } catch (Exception ignore) {
        }
    }

    public String splicingAccessTokenIndexKeyByDevice(String clientId, Object loginId, String rawDeviceId) {
        String base = KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":at-idx:" + clientId + ":" + loginId;
        return appendDeviceExplicit(base, clientId, rawDeviceId);
    }

    public String splicingRefreshTokenIndexKeyByDevice(String clientId, Object loginId, String rawDeviceId) {
        String base = KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":rt-idx:" + clientId + ":" + loginId;
        return appendDeviceExplicit(base, clientId, rawDeviceId);
    }

    @Override
    public String splicingClientTokenSaveKey(String clientToken) {
        return KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":ct:" + clientToken;
    }

    @Override
    public String splicingClientTokenIndexKey(String clientId) {
        return KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":ct-idx:" + clientId;
    }

    @Override
    public String splicingPastTokenIndexKey(String clientId) {
        return KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":ct-past:" + clientId;
    }

    @Override
    public String splicingGrantScopeKey(String clientId, Object loginId) {
        String base = KEY_PREFIX + TenantContext.getTenantIdOrDefault() + ":grant:" + clientId + ":" + loginId;
        return appendDeviceIfNeeded(base, clientId);
    }

    /**
     * 为后台管理 client 追加 deviceId，避免同一账号同一 client 多端登录时互相覆盖 token 索引。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>当前仅对后台 BFF client（默认 boot-cloud-admin-web）生效。</li>
     *   <li>deviceId 由 boot-cloud-web 生成，并作为 form 参数 device_id 透传到 /oauth/token。</li>
     * </ul>
     */
    private String appendDeviceIfNeeded(String baseKey, String clientId) {
        if (!StringUtils.hasText(baseKey) || !StringUtils.hasText(clientId)) {
            return baseKey;
        }
        // 说明：多会话配置已从 admin-multi-session 升级为 multi-session
        // 兼容策略见 AuthServerProperties.effectiveMultiSession()
        AuthServerProperties.MultiSessionConfig cfg = properties != null ? properties.effectiveMultiSession() : null;
        if (cfg == null || !cfg.isEnabled()) {
            return baseKey;
        }
        if (cfg.getClientIds() == null || cfg.getClientIds().isEmpty()) {
            return baseKey;
        }

        boolean match = cfg.getClientIds().stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .anyMatch(x -> x.equals(clientId));
        if (!match) {
            return baseKey;
        }

        String deviceId = safeDeviceId(resolveDeviceIdFromRequest(cfg));
        if (!StringUtils.hasText(deviceId)) {
            log.debug("多会话：deviceId 缺失，索引不追加 deviceId，clientId={}", clientId);
            return baseKey;
        }

        return baseKey + ":dev:" + deviceId;
    }

    private String appendDeviceExplicit(String baseKey, String clientId, String rawDeviceId) {
        if (!StringUtils.hasText(baseKey) || !StringUtils.hasText(clientId)) {
            return baseKey;
        }
        AuthServerProperties.MultiSessionConfig cfg = properties != null ? properties.effectiveMultiSession() : null;
        if (cfg == null || !cfg.isEnabled()) {
            return baseKey;
        }
        if (cfg.getClientIds() == null || cfg.getClientIds().isEmpty()) {
            return baseKey;
        }
        boolean match = cfg.getClientIds().stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .anyMatch(x -> x.equals(clientId));
        if (!match) {
            return baseKey;
        }
        String deviceId = safeDeviceId(rawDeviceId);
        if (!StringUtils.hasText(deviceId)) {
            return baseKey;
        }
        return baseKey + ":dev:" + deviceId;
    }

    private String resolveDeviceIdFromRequest(AuthServerProperties.MultiSessionConfig cfg) {
        try {
            String paramName = (cfg != null && StringUtils.hasText(cfg.getDeviceIdParamName()))
                    ? cfg.getDeviceIdParamName()
                    : "device_id";
            String fromParam = SaHolder.getRequest().getParam(paramName);
            if (StringUtils.hasText(fromParam)) {
                return fromParam;
            }
            return SaHolder.getRequest().getHeader("X-Device-Id");
        } catch (Exception e) {
            // 某些场景不在 HTTP 请求上下文中
            return null;
        }
    }

    private String safeDeviceId(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String v = raw.trim();
        int max = 64;
        if (properties != null) {
            AuthServerProperties.MultiSessionConfig cfg = properties.effectiveMultiSession();
            if (cfg != null) {
                max = Math.max(cfg.getMaxDeviceIdLength(), 16);
            }
        }

        if (v.length() <= max) {
            return sanitizeKeySegment(v);
        }

        // 过长则 hash，避免 Redis Key 过长
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(v.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest).substring(0, 32);
        } catch (Exception e) {
            return sanitizeKeySegment(v.substring(0, max));
        }
    }

    private String sanitizeKeySegment(String v) {
        if (!StringUtils.hasText(v)) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '_' || c == '-' || c == '.';
            if (ok) {
                sb.append(c);
            }
        }
        String out = sb.toString();
        return StringUtils.hasText(out) ? out : null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private boolean matchSecret(String stored, String provided) {
        if (!StringUtils.hasText(provided)) {
            return false;
        }
        // BCrypt：生产推荐只存 hash（$2a/$2b/$2y），这里兼容存明文的过渡期数据
        if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
            return passwordEncoder.matches(provided, stored);
        }
        return stored.equals(provided);
    }

    private static Set<String> splitCsvLower(String csv) {
        return split(csv).stream().map(s -> s.toLowerCase()).collect(Collectors.toSet());
    }

    /**
     * scope 统一规范成 CSV，便于 Sa-Token OAuth2 的 {@code convertStringToList} 校验。
     */
    private static String normalizeScopeCsv(String raw) {
        List<String> parts = split(raw);
        return String.join(",", parts);
    }

    private static List<String> split(String csvOrSpaces) {
        if (!StringUtils.hasText(csvOrSpaces)) {
            return List.of();
        }
        return Arrays.stream(csvOrSpaces.split("[,\\s]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }

    private static List<String> parseRedirectUris(String raw) {
        if (!StringUtils.hasText(raw)) {
            return List.of();
        }
        String s = raw.trim();
        // 允许 JSON 数组（例如 ["https://a/cb","https://b/cb"]），这里做轻量解析即可
        if (s.startsWith("[") && s.endsWith("]")) {
            String inner = s.substring(1, s.length() - 1).trim();
            if (inner.isEmpty()) {
                return List.of();
            }
            return Arrays.stream(inner.split(","))
                    .map(String::trim)
                    .map(v -> v.replaceAll("^\"|\"$", ""))
                    .filter(StringUtils::hasText)
                    .toList();
        }
        return split(s);
    }
}
