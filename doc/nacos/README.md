# Nacos 模板说明

`doc/nacos/` 下的文件是 `boot-cloud` 的推荐 DataId 模板，目标是让新项目可以按模块拆分配置，同时保持公共配置可复用。

推荐 DataId 划分：

- `boot-cloud-common.yaml`
  - 放框架层共用配置，例如日志、国际化、链路追踪。
- `boot-cloud-db.yaml`
  - 放 MySQL、Redis、MyBatis-Plus 等基础数据访问配置。
- `boot-cloud-mq.yaml`
  - 放 RocketMQ 等消息队列配置。
- `boot-cloud-oauth-common.yaml`
  - 放 OAuth2、资源服务、内部调用鉴权、公共白名单等跨服务安全配置。
- `boot-cloud-auth.yaml`
  - 放认证中心独有配置。
- `boot-cloud-base.yaml`
  - 放基础治理中心独有配置。
- `boot-cloud-gateway.yaml`
  - 放网关路由、租户解析、风控等配置。
- `boot-cloud-web.yaml`
  - 放 BFF 独有配置。

推荐引入顺序：

1. `boot-cloud-common.yaml`
2. `boot-cloud-db.yaml`
3. `boot-cloud-mq.yaml`
4. `boot-cloud-oauth-common.yaml`
5. 当前服务私有 DataId

建议：

- 敏感项例如数据库密码、`client-secret`、`internal-service-secret` 不要提交真实值。
- 公共 DataId 只放跨服务真正共享的配置，避免配置中心逐渐失控。
- 私有 DataId 只放当前服务的专属配置，便于后续独立演进。
