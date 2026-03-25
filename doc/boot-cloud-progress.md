# boot-cloud-progress

## 已完成

- `2026-03-25 v0.1.0`
  - 初始化多模块 Maven 工程
  - 完成 `components`、`platform`、`services` 三层结构搭建
  - 落地第一版 Nacos 模板、README 与构建脚本
  - 执行 `mvn -DskipTests compile`，结果 `BUILD SUCCESS`

- `2026-03-25 v0.2.0`
  - 完成 Java 包根迁移，统一为 `com.bootcloud`
  - 统一 Maven 坐标、服务注册名与模块命名为 `boot-cloud-*`
  - 清理第三方登录、专有会话交换等强业务耦合代码
  - 保留网关、认证中心、配置治理与 BFF 的通用骨架
  - 执行 `mvn -DskipTests compile`，结果 `BUILD SUCCESS`

- `2026-03-25 v0.3.0`
  - 将服务端配置前缀统一收口为 `boot.cloud.*`
  - 重建认证中心主配置模型，保留租户控制、多会话、设备会话、MFA、客户端缓存等通用能力
  - 清理公共错误码中的业务领域常量，保留脚手架级别通用错误码
  - 删除旧兼容桥接类，统一资源服务与认证客户端属性模型
  - 执行 `mvn -DskipTests compile`，结果 `BUILD SUCCESS`

- `2026-03-25 v0.4.0`
  - 批量重命名残留的历史类名为通用语义名
  - 重写根文档、认证中心文档与 Nacos 说明，收敛为通用脚手架描述
  - 统一内部鉴权、Trace、版本治理等配置与命名
  - 执行 `mvn -DskipTests compile`，结果 `BUILD SUCCESS`

- `2026-03-25 v0.5.0`
  - 清理默认头名、Cookie 名、容器目录结构中的历史命名污染
  - 重命名残留 Feign 接口与表单编码器内部类，统一源码风格
  - 重写 `doc/nacos/` 全部模板，收敛为最小可用的通用配置示例
  - 更新根 README 与交付说明，形成可直接复用的新项目脚手架
  - 执行源码残留扫描与 `mvn -DskipTests compile` 验证

## 已确认决策

- Java 包根统一使用 `com.bootcloud`
- 配置前缀统一使用 `boot.cloud.*`
- 公共层仅保留横切能力，不沉淀业务领域代码
- 平台层保留 `gateway`、`auth`、`base`
- `boot-cloud-web` 仅作为通用 BFF 示例，不承载业务私有逻辑
- 默认内部 Header、Cookie 与 Redis Key 前缀统一使用 `boot-cloud` 语义
- Nacos 模板只保留脚手架级最小配置，不再承载历史业务示例

## 待办

- 补齐 SQL 基线与初始化脚本模板
- 为更多业务服务提供最小接入示例
- 补充集成测试与容器编排样例

## 已知坑位

- `AesGcmTicketCipher` 仍有 unchecked warning，后续可单独做类型安全收敛
