package com.bootcloud.gateway.core.risk;

/**
 * GateShield 决策结果。
 */
public record RiskDecision(
        boolean blocked,
        String code,
        String message,
        String ruleType,
        String ruleValue
) {

    public static RiskDecision allow() {
        return new RiskDecision(false, "", "", "", "");
    }

    public static RiskDecision block(String code, String message, String ruleType, String ruleValue) {
        return new RiskDecision(true, code, message, ruleType, ruleValue);
    }
}

