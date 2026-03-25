package com.bootcloud.common.feign.dto.base;

import lombok.Data;

import java.util.List;

/**
 * API Scope 动态规则更新请求。
 */
@Data
public class BaseApiScopeRuleConfigUpdateRequest {

    /**
     * 默认策略：LEGACY 或 DENY。
     */
    private String defaultPolicy;

    /**
     * 全量规则列表。
     */
    private List<BaseApiScopeRuleItem> rules;

    /**
     * 更新人。
     */
    private String updatedBy;

    /**
     * 更新备注。
     */
    private String remark;
}
