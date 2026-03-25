package com.bootcloud.auth.core.client;

public interface ClientRegistry {
    OAuthClient findClient(long tenantId, String clientId);
}

