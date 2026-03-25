package com.bootcloud.common.feign.dto.base;

import lombok.Data;

import java.util.List;

/**
 * API Scope 动态规则项。
 */
@Data
public class BaseApiScopeRuleItem {

    /**
     * 规则标识。
     */
    private String ruleId;

    /**
     * 1 启用 0 禁用。
     */
    private Integer enabled;

    /**
     * HTTP 方法：GET/POST/PUT/PATCH/DELETE/*。
     */
    private String method;

    /**
     * 接口路径模式，支持 Ant 风格。
     */
    private String pathPattern;

    /**
     * 要求的 scope 列表。
     */
    private List<String> requiredScopes;

    /**
     * 命中策略：ANY 或 ALL。
     */
    private String matchMode;

    /**
     * 优先级，数字越小越优先。
     */
    private Integer priority;

    /**
     * 备注。
     */
    private String remark;
}
