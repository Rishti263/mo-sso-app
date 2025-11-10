package com.ssoapp.controller;

import com.ssoapp.config.TenantContext;
import com.ssoapp.model.SsoConfig;
import com.ssoapp.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuthController {

    private final SsoConfigService ssoConfigService;

    @GetMapping("/authorize")
    public ResponseEntity<?> authorize() {
        Long organizationId = TenantContext.getOrganizationId();

        if (organizationId == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonMap("error", "OAuth not available for superadmin"));
        }

        SsoConfig config = ssoConfigService.getEnabledConfig(organizationId, "OAUTH")
                .orElseThrow(() -> new RuntimeException("OAuth not configured"));

        String authUrl = config.getAuthorizationUri() +
                "?client_id=" + config.getClientId() +
                "&response_type=code" +
                "&redirect_uri=http://localhost:8080/oauth2/callback";

        return ResponseEntity.ok(Collections.singletonMap("authorizationUrl", authUrl));
    }

    @GetMapping("/callback")
    public ResponseEntity<?> callback(@RequestParam("code") String code) {
        try {
            Long organizationId = TenantContext.getOrganizationId();

            if (organizationId == null) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Collections.singletonMap("error", "OAuth not available for superadmin"));
            }

            SsoConfig config = ssoConfigService.getEnabledConfig(organizationId, "OAUTH")
                    .orElseThrow(() -> new RuntimeException("OAuth not configured"));

            // TODO: Exchange code for token and authenticate user
            log.info("OAuth callback received for organization: {}", organizationId);

            return ResponseEntity.ok(Collections.singletonMap("message", "OAuth authentication successful"));
        } catch (Exception e) {
            log.error("OAuth callback failed", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }
}