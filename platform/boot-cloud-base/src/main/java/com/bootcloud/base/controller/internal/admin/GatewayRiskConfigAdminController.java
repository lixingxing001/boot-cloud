package com.bootcloud.base.controller.internal.admin;

import com.bootcloud.base.core.gateshield.GatewayRiskConfigService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 内部管理接口：网关 GateShield 配置管理。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>管理端服务 用该接口写入 DB 配置。</li>
 *   <li>boot-cloud-gateway 用该接口拉取最新配置快照。</li>
 * </ul>
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/admin/gateway-risk-config")
public class GatewayRiskConfigAdminController {

    private final GatewayRiskConfigService gatewayRiskConfigService;

    @GetMapping("/current")
    public GatewayRiskConfigService.Snapshot current() {
        GatewayRiskConfigService.Snapshot snapshot = gatewayRiskConfigService.getCurrent();
        if (log.isDebugEnabled()) {
            log.debug("查询 GateShield 配置：configCode={}, version={}", snapshot.configCode(), snapshot.version());
        }
        return snapshot;
    }

    @PutMapping
    public GatewayRiskConfigService.Snapshot update(@Valid @RequestBody UpdateRequest request) {
        String updatedBy = StringUtils.hasText(request.updatedBy()) ? request.updatedBy().trim() : "unknown";
        GatewayRiskConfigService.Snapshot snapshot = gatewayRiskConfigService.update(
                request.payload(),
                updatedBy,
                request.remark()
        );
        log.info("更新 GateShield 配置完成：updatedBy={}, version={}", updatedBy, snapshot.version());
        return snapshot;
    }

    public record UpdateRequest(
            @NotNull(message = "payload 不能为空")
            Map<String, Object> payload,
            String updatedBy,
            String remark
    ) {
    }
}
