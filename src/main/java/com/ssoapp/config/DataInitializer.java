package com.ssoapp.config;

import com.ssoapp.model.Organization;
import com.ssoapp.model.User;
import com.ssoapp.repository.OrganizationRepository;
import com.ssoapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Create superadmin user if not exists
        if (!userRepository.existsByUsernameAndOrganizationIsNull("superadmin")) {
            User superadmin = new User();
            superadmin.setUsername("superadmin");
            superadmin.setPassword(passwordEncoder.encode("admin123"));
            superadmin.setEmail("superadmin@example.com");
            superadmin.setRole("ROLE_SUPER_ADMIN");
            superadmin.setOrganization(null);
            userRepository.save(superadmin);
            log.info("Superadmin user created");
        }

        // Create demo organization if not exists
        if (!organizationRepository.existsBySubdomain("demo")) {
            Organization demoOrg = new Organization();
            demoOrg.setName("Demo Organization");
            demoOrg.setSubdomain("demo");
            demoOrg = organizationRepository.save(demoOrg);

            User demoAdmin = new User();
            demoAdmin.setUsername("demoadmin");
            demoAdmin.setPassword(passwordEncoder.encode("demo123"));
            demoAdmin.setEmail("admin@demo.com");
            demoAdmin.setRole("ROLE_ADMIN");
            demoAdmin.setOrganization(demoOrg);
            userRepository.save(demoAdmin);

            log.info("Demo organization and admin created");
        }
    }
}
