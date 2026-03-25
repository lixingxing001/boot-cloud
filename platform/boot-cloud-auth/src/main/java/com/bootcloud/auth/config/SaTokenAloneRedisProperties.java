package com.bootcloud.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * 绑定 Sa-Token 的独立 Redis 配置（来自 Nacos 的 {@code boot-cloud-oauth-common.yaml} 中 {@code sa-token.alone-redis}）。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>原项目使用 Sa-Token 的 {@code alone-redis} 插件来隔离认证/授权 Redis（db=7）。</li>
 *   <li>当前重构阶段为了减少外部依赖拉取失败的风险，我们在 boot-cloud-auth 内部用 Spring Data Redis 手动创建同等效果的连接。</li>
 *   <li>这样既保留了配置形态（Nacos 文件不需要改），又能确保 OAuth2 token 存在独立 Redis DB。</li>
 * </ul>
 */
@Data
@ConfigurationProperties(prefix = "sa-token.alone-redis")
public class SaTokenAloneRedisProperties {

    /**
     * Redis DB 索引，默认 0；现有 nacos 配置一般设为 7。
     */
    private int database = 0;

    private String host = "127.0.0.1";

    private int port = 6379;

    private String password;

    /**
     * Redis 命令超时（例如 10s）。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>该配置会映射到 Lettuce 的 commandTimeout。</li>
     *   <li>当 Redis 卡顿或网络抖动时，命令超过该时长会抛出 {@code RedisCommandTimeoutException}。</li>
     * </ul>
     */
    private Duration timeout = Duration.ofSeconds(10);

    /**
     * 连接超时（建立 TCP 连接的超时）。
     *
     * <p>说明：建议设短一些，用于快速识别 Redis 不可达或网络异常。</p>
     */
    private Duration connectTimeout = Duration.ofSeconds(1);

    /**
     * 是否启用连接校验。
     *
     * <p>说明：</p>
     * <ul>
     *   <li>启用后，连接失效时更容易在下一次请求时被识别并重建。</li>
     *   <li>会带来轻微额外开销，若压测发现性能敏感可关闭。</li>
     * </ul>
     */
    private boolean validateConnection = true;

    /**
     * 启动时是否做一次 Redis PING 以便快速暴露连接问题。
     *
     * <p>说明：默认关闭，避免在 Redis 暂不可用时影响服务启动节奏；需要时可在 Nacos 打开。</p>
     */
    private boolean startupCheckEnabled = false;
}

