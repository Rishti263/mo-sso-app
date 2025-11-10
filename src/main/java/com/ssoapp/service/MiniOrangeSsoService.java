package com.ssoapp.service;

import com.ssoapp.config.MiniOrangeJwtValidator;
import com.ssoapp.config.TenantContext;
import com.ssoapp.model.SsoConfig;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class MiniOrangeSsoService {

    private final SsoConfigService ssoConfigService;
    private final MiniOrangeJwtValidator jwtValidator;

    public Claims processSsoToken(String token) {
        Long organizationId = TenantContext.getOrganizationId();

        if (organizationId == null) {
            throw new RuntimeException("SSO not available for superadmin domain");
        }

        SsoConfig config = ssoConfigService.getEnabledConfig(organizationId, "MINIORANGE")
                .orElseThrow(() -> new RuntimeException("MiniOrange SSO not configured for this organization"));

        return jwtValidator.validateAndParseToken(token, config.getMiniOrangePublicKey());
    }
}