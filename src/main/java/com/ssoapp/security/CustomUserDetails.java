package com.ssoapp.security;

import com.ssoapp.model.User;          // align with your JPA package
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;            // <-- import this

public class CustomUserDetails implements UserDetails {

    private final User user;

    public CustomUserDetails(User user) { this.user = user; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String role = (user.getRole() == null ? "ENDUSER" : user.getRole().trim().toUpperCase());
        if (!role.startsWith("ROLE_")) role = "ROLE_" + role;
        return Collections.singletonList(new SimpleGrantedAuthority(role)); // <-- Java 8 safe
    }

    @Override public String getPassword() { return user.getPassword(); }
    @Override public String getUsername() { return user.getUsername(); }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }

    public Long getOrganizationId() {
        return user.getOrganization() != null ? user.getOrganization().getId() : null;
    }
}
