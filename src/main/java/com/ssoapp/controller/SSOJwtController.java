package com.ssoapp.controller;

import com.ssoapp.config.JwtUtil;
import com.ssoapp.config.TenantContext;
import com.ssoapp.model.User;
import com.ssoapp.repository.UserRepository;
import com.ssoapp.security.CustomUserDetails;
import com.ssoapp.service.MiniOrangeSsoService;
import io.jsonwebtoken.Claims;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/sso")
@RequiredArgsConstructor
@Slf4j
public class SSOJwtController {

    private final MiniOrangeSsoService miniOrangeSsoService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @PostMapping("/jwt/validate")
    public ResponseEntity<?> validateSsoJwt(@RequestBody SsoJwtRequest request) {
        try {
            Long organizationId = TenantContext.getOrganizationId();

            if (organizationId == null) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Collections.singletonMap("error", "SSO not available for superadmin domain"));
            }

            Claims claims = miniOrangeSsoService.processSsoToken(request.getToken());
            String username = claims.getSubject();
            String email = claims.get("email", String.class);

            // Find or create user
            User user = userRepository.findByUsernameAndOrganizationId(username, organizationId)
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setUsername(username);
                        newUser.setEmail(email != null ? email : username + "@example.com");
                        newUser.setPassword(""); // SSO users don't have password
                        newUser.setRole("ROLE_USER");
                        newUser.setOrganization(userRepository.findById(organizationId)
                                .orElseThrow().getOrganization());
                        return userRepository.save(newUser);
                    });

            CustomUserDetails userDetails = new CustomUserDetails(user);
            String jwtToken = jwtUtil.generateToken(userDetails, organizationId);

            Map<String, Object> response = new HashMap<>();
            response.put("token", jwtToken);
            response.put("username", user.getUsername());
            response.put("role", user.getRole());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("SSO JWT validation failed", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid SSO token"));
        }
    }

    @Data
    static class SsoJwtRequest {
        private String token;
    }
}