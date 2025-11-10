package com.ssoapp.service;

import com.ssoapp.config.TenantContext;
import com.ssoapp.model.User;
import com.ssoapp.repository.UserRepository;
import com.ssoapp.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Long organizationId = TenantContext.getOrganizationId();
        log.debug("Loading user: {} for organizationId: {}", username, organizationId);

        User user;
        if (organizationId == null) {
            // Superadmin domain
            user = userRepository.findByUsernameAndOrganizationIsNull(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        } else {
            // Tenant domain
            user = userRepository.findByUsernameAndOrganizationId(username, organizationId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        }

        return new CustomUserDetails(user);
    }
}
