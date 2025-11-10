package com.ssoapp.controller;

import com.ssoapp.config.TenantContext;
import com.ssoapp.model.Organization;
import com.ssoapp.repository.OrganizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/tenant")
@RequiredArgsConstructor
public class ApiController {

    private final OrganizationRepository organizationRepository;

    @GetMapping("/info")
    public ResponseEntity<?> getTenantInfo() {
        Long organizationId = TenantContext.getOrganizationId();

        Map<String, Object> response = new HashMap<>();
        response.put("isSuperadmin", organizationId == null);
        response.put("organizationId", organizationId);

        if (organizationId != null) {
            Organization org = organizationRepository.findById(organizationId).orElse(null);
            if (org != null) {
                response.put("organizationName", org.getName());
                response.put("subdomain", org.getSubdomain());
            }
        }

        return ResponseEntity.ok(response);
    }
}
