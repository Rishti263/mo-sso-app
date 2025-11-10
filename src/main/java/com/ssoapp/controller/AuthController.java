package com.ssoapp.controller;

import com.ssoapp.config.JwtUtil;
import com.ssoapp.config.TenantContext;
import com.ssoapp.model.User;
import com.ssoapp.security.CustomUserDetails;
import com.ssoapp.service.CustomUserDetailsService;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpSession session) {
        try {
            Long organizationId = TenantContext.getOrganizationId();
            log.info("Login attempt for user: {} with organizationId: {}", request.getUsername(), organizationId);

            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            // IMPORTANT: Set the authentication in SecurityContext
            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(authentication);

            // Save the SecurityContext in the session
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            CustomUserDetails customUserDetails = (CustomUserDetails) userDetails;

            // Generate JWT token (for API calls)
            String token = jwtUtil.generateToken(userDetails, customUserDetails.getOrganizationId());

            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            response.put("username", userDetails.getUsername());
            response.put("role", customUserDetails.getAuthorities().iterator().next().getAuthority());
            response.put("organizationId", customUserDetails.getOrganizationId());

            log.info("Login successful for user: {} with role: {}", request.getUsername(),
                    customUserDetails.getAuthorities().iterator().next().getAuthority());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Login failed for user: {}", request.getUsername(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
        try {
            Long organizationId = TenantContext.getOrganizationId();
            log.info("Signup attempt with organizationId: {}", organizationId);

            User user = userService.createUser(
                    request.getUsername(),
                    request.getPassword(),
                    request.getEmail(),
                    request.getOrganizationName(),
                    request.getSubdomain()
            );

            Map<String, Object> response = new HashMap<>();
            response.put("message", "User created successfully");
            response.put("username", user.getUsername());
            response.put("role", user.getRole());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Signup failed", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @Data
    static class LoginRequest {
        private String username;
        private String password;
    }

    @Data
    static class SignupRequest {
        private String username;
        private String password;
        private String email;
        private String organizationName;
        private String subdomain;
    }
}