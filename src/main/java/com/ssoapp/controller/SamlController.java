package com.ssoapp.controller;

import com.ssoapp.config.TenantContext;
import com.ssoapp.model.SsoConfig;
import com.ssoapp.service.SamlMetadataService;
import com.ssoapp.service.SsoConfigService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/saml")
@RequiredArgsConstructor
@Slf4j
public class SamlController {

    private final SsoConfigService ssoConfigService;
    private final SamlMetadataService samlMetadataService;

    @GetMapping("/metadata")
    public ResponseEntity<String> getMetadata() {
        Long organizationId = TenantContext.getOrganizationId();

        if (organizationId == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("SAML not available for superadmin");
        }

        String entityId = "urn:example:sp:" + organizationId;
        String acsUrl = "http://localhost:8080/saml/acs";
        String metadata = samlMetadataService.generateMetadata(entityId, acsUrl);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_XML)
                .body(metadata);
    }

    @PostMapping("/acs")
    public ResponseEntity<?> assertionConsumerService(@RequestParam("SAMLResponse") String samlResponse) {
        try {
            Long organizationId = TenantContext.getOrganizationId();

            if (organizationId == null) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Collections.singletonMap("error", "SAML not available for superadmin"));
            }

            SsoConfig config = ssoConfigService.getEnabledConfig(organizationId, "SAML")
                    .orElseThrow(() -> new RuntimeException("SAML not configured"));

            // TODO: Implement actual SAML response validation and user authentication
            log.info("SAML ACS called for organization: {}", organizationId);

            return ResponseEntity.ok(Collections.singletonMap("message", "SAML authentication successful"));
        } catch (Exception e) {
            log.error("SAML ACS failed", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping("/slo")
    public ResponseEntity<?> singleLogout() {
        log.info("SAML SLO called");
        return ResponseEntity.ok(Collections.singletonMap("message", "Logged out successfully"));
    }
}