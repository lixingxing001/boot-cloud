package com.bootcloud.auth.core.user;

import java.util.Set;

public record UserPrincipal(String userId, Set<String> scopes) {
}

