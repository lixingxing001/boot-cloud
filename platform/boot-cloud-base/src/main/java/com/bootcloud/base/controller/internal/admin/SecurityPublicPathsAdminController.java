package com.bootcloud.base.controller.internal.admin;

import com.bootcloud.base.core.security.SecurityPublicPathsConfigService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 内部管理接口：公共白名单路径配置。
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/admin/security-public-paths")
public class SecurityPublicPathsAdminController {

    private final SecurityPublicPathsConfigService securityPublicPathsConfigService;

    @GetMapping("/current")
    public SecurityPublicPathsConfigService.Snapshot current() {
        SecurityPublicPathsConfigService.Snapshot snapshot = securityPublicPathsConfigService.getCurrent();
        if (log.isDebugEnabled()) {
            log.debug("查询公共白名单配置：version={}, pathCount={}, source={}",
                    snapshot.version(),
                    snapshot.publicPaths() == null ? 0 : snapshot.publicPaths().size(),
                    snapshot.source());
        }
        return snapshot;
    }

    @PutMapping
    public SecurityPublicPathsConfigService.Snapshot update(@Valid @RequestBody UpdateRequest request) {
        SecurityPublicPathsConfigService.Snapshot snapshot = securityPublicPathsConfigService.update(
                request.getPublicPaths(),
                request.getUpdatedBy(),
                request.getRemark()
        );
        log.info("更新公共白名单配置完成：version={}, pathCount={}, updatedBy={}",
                snapshot.version(),
                snapshot.publicPaths() == null ? 0 : snapshot.publicPaths().size(),
                snapshot.updatedBy());
        return snapshot;
    }

    @Data
    public static class UpdateRequest {
        /**
         * 全量公共白名单路径。
         */
        @NotNull(message = "publicPaths 不能为空")
        private List<String> publicPaths;

        /**
         * 更新人。
         */
        private String updatedBy;

        /**
         * 更新备注。
         */
        private String remark;
    }
}
