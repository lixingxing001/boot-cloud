package com.bootcloud.base.controller.internal.admin;

import com.bootcloud.base.core.oauth.ApiScopeRuleConfigService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * 内部管理接口：API Scope 动态规则管理。
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/admin/api-scope-rules")
public class ApiScopeRuleAdminController {

    private final ApiScopeRuleConfigService apiScopeRuleConfigService;

    @GetMapping("/current")
    public ApiScopeRuleConfigService.Snapshot current() {
        ApiScopeRuleConfigService.Snapshot snapshot = apiScopeRuleConfigService.getCurrent();
        if (log.isDebugEnabled()) {
            log.debug("查询 API Scope 动态规则：version={}, defaultPolicy={}, ruleCount={}",
                    snapshot.version(),
                    snapshot.defaultPolicy(),
                    snapshot.rules() == null ? 0 : snapshot.rules().size());
        }
        return snapshot;
    }

    @PutMapping
    public ApiScopeRuleConfigService.Snapshot update(@Valid @RequestBody UpdateRequest request) {
        List<ApiScopeRuleConfigService.RuleItem> rules = toRules(request.getRules());
        ApiScopeRuleConfigService.Snapshot snapshot = apiScopeRuleConfigService.update(
                rules,
                request.getDefaultPolicy(),
                request.getUpdatedBy(),
                request.getRemark()
        );
        log.info("更新 API Scope 动态规则完成：version={}, defaultPolicy={}, ruleCount={}, updatedBy={}",
                snapshot.version(),
                snapshot.defaultPolicy(),
                snapshot.rules() == null ? 0 : snapshot.rules().size(),
                snapshot.updatedBy());
        return snapshot;
    }

    private static List<ApiScopeRuleConfigService.RuleItem> toRules(List<RuleItem> items) {
        if (items == null || items.isEmpty()) {
            return List.of();
        }
        List<ApiScopeRuleConfigService.RuleItem> out = new ArrayList<>();
        for (RuleItem item : items) {
            if (item == null) {
                continue;
            }
            ApiScopeRuleConfigService.RuleItem mapped = new ApiScopeRuleConfigService.RuleItem();
            mapped.setRuleId(StringUtils.hasText(item.getRuleId()) ? item.getRuleId().trim() : null);
            mapped.setEnabled(item.getEnabled());
            mapped.setMethod(item.getMethod());
            mapped.setPathPattern(item.getPathPattern());
            mapped.setRequiredScopes(item.getRequiredScopes());
            mapped.setMatchMode(item.getMatchMode());
            mapped.setPriority(item.getPriority());
            mapped.setRemark(item.getRemark());
            out.add(mapped);
        }
        return out;
    }

    @Data
    public static class UpdateRequest {
        /**
         * 默认策略：LEGACY 或 DENY。
         */
        @NotBlank(message = "defaultPolicy 不能为空")
        private String defaultPolicy;

        @NotNull(message = "rules 不能为空")
        private List<RuleItem> rules;

        private String updatedBy;

        private String remark;
    }

    @Data
    public static class RuleItem {
        private String ruleId;
        private Integer enabled;
        private String method;
        private String pathPattern;
        private List<String> requiredScopes;
        private String matchMode;
        private Integer priority;
        private String remark;
    }
}
