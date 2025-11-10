package com.ssoapp.controller;

import com.ssoapp.model.Organization;
import com.ssoapp.model.User;
import com.ssoapp.repository.OrganizationRepository;
import com.ssoapp.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Collections;
import java.util.List;

@Controller
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class SuperadminController {

    private final OrganizationRepository organizationRepository;
    private final AdminService adminService;

    @GetMapping("/dashboard")
    public String superadminDashboard(Model model, Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return "redirect:/login";
        }

        String username = extractUsername(auth);

        // Fetch real data
        List<Organization> organizations = organizationRepository.findAll();
        List<User> superadmins = adminService.getAllSuperadminUsers();

        model.addAttribute("username", username);
        model.addAttribute("organizations", organizations != null ? organizations : Collections.emptyList());
        model.addAttribute("superadmins", superadmins != null ? superadmins : Collections.emptyList());

        return "superadmin-dashboard";
    }

    private String extractUsername(Authentication auth) {
        Object p = auth.getPrincipal();
        if (p instanceof com.ssoapp.security.CustomUserDetails) {
            return ((com.ssoapp.security.CustomUserDetails) p).getUsername();
        }
        if (p instanceof org.springframework.security.core.userdetails.User) {
            return ((org.springframework.security.core.userdetails.User) p).getUsername();
        }
        return String.valueOf(p);
    }
}