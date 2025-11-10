package com.ssoapp.service;

import com.ssoapp.config.TenantContext;
import com.ssoapp.model.Organization;
import com.ssoapp.model.User;
import com.ssoapp.repository.OrganizationRepository;
import com.ssoapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User createUser(String username, String password, String email, String organizationName, String subdomain) {
        Long organizationId = TenantContext.getOrganizationId();
        log.info("Creating user for organizationId: {}", organizationId);

        if (organizationId == null) {
            // Superadmin domain: create new organization and admin user
            if (organizationRepository.existsBySubdomain(subdomain)) {
                throw new RuntimeException("Organization with subdomain " + subdomain + " already exists");
            }

            Organization organization = new Organization();
            organization.setName(organizationName);
            organization.setSubdomain(subdomain);
            organization = organizationRepository.save(organization);

            User user = new User();
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(password));
            user.setEmail(email);
            user.setRole("ROLE_ADMIN");
            user.setOrganization(organization);

            log.info("Created new organization {} and admin user {}", organizationName, username);
            return userRepository.save(user);
        } else {
            // Tenant domain: create new user for existing organization
            Organization organization = organizationRepository.findById(organizationId)
                    .orElseThrow(() -> new RuntimeException("Organization not found"));

            if (userRepository.existsByUsernameAndOrganizationId(username, organizationId)) {
                throw new RuntimeException("User already exists in this organization");
            }

            User user = new User();
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(password));
            user.setEmail(email);
            user.setRole("ROLE_USER");
            user.setOrganization(organization);

            log.info("Created new user {} for organization {}", username, organization.getName());
            return userRepository.save(user);
        }
    }
}