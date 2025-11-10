package com.ssoapp.config;


import com.ssoapp.model.Organization;
import com.ssoapp.repository.OrganizationRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class TenantIdentifierFilter extends OncePerRequestFilter {

    private final OrganizationRepository organizationRepository;

    @Value("${app.superadmin.domain:superadmin.localhost}")
    private String superadminDomain;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String host = request.getServerName();
            log.debug("Processing request for host: {}", host);

            if (host.equals(superadminDomain)) {
                TenantContext.setOrganizationId(null);
                log.debug("Superadmin domain detected, organizationId set to null");
            } else {
                String subdomain = extractSubdomain(host);
                if (subdomain != null && !subdomain.isEmpty()) {
                    Organization org = organizationRepository.findBySubdomain(subdomain).orElse(null);
                    if (org != null) {
                        TenantContext.setOrganizationId(org.getId());
                        log.debug("Tenant domain detected: {}, organizationId: {}", subdomain, org.getId());
                    } else {
                        log.warn("No organization found for subdomain: {}", subdomain);
                        TenantContext.setOrganizationId(null);
                    }
                } else {
                    TenantContext.setOrganizationId(null);
                }
            }

            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private String extractSubdomain(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }

        // Remove port if present
        String hostWithoutPort = host.split(":")[0];

        // For localhost testing: acme.localhost -> acme
        if (hostWithoutPort.endsWith(".localhost")) {
            String[] parts = hostWithoutPort.split("\\.");
            if (parts.length >= 2) {
                return parts[0];
            }
        }

        // For production: acme.example.com -> acme
        String[] parts = hostWithoutPort.split("\\.");
        if (parts.length > 2) {
            return parts[0];
        }

        return null;
    }
}