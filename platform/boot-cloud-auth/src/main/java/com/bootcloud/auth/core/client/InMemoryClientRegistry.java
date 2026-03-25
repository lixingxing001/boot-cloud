package com.bootcloud.auth.core.client;

import com.bootcloud.auth.config.AuthServerProperties;

import java.util.HashMap;
import java.util.Map;

public class InMemoryClientRegistry implements ClientRegistry {

    private final Map<String, OAuthClient> clients = new HashMap<>();

    public InMemoryClientRegistry(AuthServerProperties properties) {
        for (AuthServerProperties.ClientConfig cfg : properties.getClients()) {
            OAuthClient client = OAuthClient.fromConfig(cfg);
            clients.put(key(cfg.getTenantId(), cfg.getClientId()), client);
        }
    }

    @Override
    public OAuthClient findClient(long tenantId, String clientId) {
        return clients.get(key(tenantId, clientId));
    }

    private static String key(long tenantId, String clientId) {
        return tenantId + ":" + (clientId == null ? "" : clientId.trim());
    }
}

