# boot-cloud-auth

`boot-cloud-auth` 是脚手架内的认证中心服务，负责统一签发和校验访问令牌。

当前提供的能力：

- `authorization_code`
- `password`
- `client_credentials`
- `refresh_token`
- PKCE
- Opaque Token Introspection
- Token Revocation
- 管理端专用登录模式
- 多会话与设备会话记录
- MFA 扩展点

配置入口：

- `boot.cloud.auth.*`
- `boot.cloud.auth.client.*`
- `boot.cloud.oauth2.resource-server.*`
- `boot.cloud.internal-auth.*`

本地验证：

```bash
cd /mnt/f/AI/boot-cloud
mvn -pl platform/boot-cloud-auth -am -DskipTests compile
```
