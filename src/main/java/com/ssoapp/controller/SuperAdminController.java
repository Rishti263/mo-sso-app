package com.ssoapp.controller;

import com.ssoapp.entity.User;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class SuperAdminController {

    private final UserService userService;

    @GetMapping("/dashboard")
    public String superAdminDashboard(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
            return "redirect:/login";
        }

        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("currentUser", currentUser);
        model.addAttribute("adminCount", userService.countByRole("ADMIN"));
        model.addAttribute("userCount", userService.countByRole("ENDUSER"));

        return "superadmin-dashboard";
    }

    @PostMapping("/user/create")
    @ResponseBody
    public String createUser(@RequestBody User user, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
                return "error: unauthorized";
            }

            // Super admin can create any type of user
            user.setCreatedBy(currentUser.getUsername());
            userService.registerUser(user);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @PostMapping("/user/update/{id}")
    @ResponseBody
    public String updateUser(@PathVariable Long id, @RequestBody User user) {
        try {
            userService.updateUser(id, user);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @PostMapping("/user/delete/{id}")
    @ResponseBody
    public String deleteUser(@PathVariable Long id) {
        try {
            userService.deleteUser(id);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @GetMapping("/sso-config")
    public String ssoConfig(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
            return "redirect:/login";
        }

        return "sso-config";
    }
}