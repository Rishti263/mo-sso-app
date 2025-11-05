package com.ssoapp.controller;

import com.ssoapp.entity.User;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;

    @GetMapping("/dashboard")
    public String adminDashboard(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
            return "redirect:/login";
        }

        // Admin can only see and manage end users
        List<User> users = userService.getAllUsers().stream()
                .filter(u -> "ENDUSER".equals(u.getRole()))
                .collect(Collectors.toList());

        model.addAttribute("users", users);
        model.addAttribute("currentUser", currentUser);
        return "admin-dashboard";
    }

    @PostMapping("/user/create")
    @ResponseBody
    public String createUser(@RequestBody User user, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return "error: unauthorized";
            }

            // Admin can only create ENDUSER
            user.setRole("ENDUSER");
            user.setCreatedBy(currentUser.getUsername());
            userService.registerUser(user);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @PostMapping("/user/update/{id}")
    @ResponseBody
    public String updateUser(@PathVariable Long id, @RequestBody User user, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return "error: unauthorized";
            }

            // Admin can only update ENDUSER
            User existingUser = userService.getUserById(id)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (!"ENDUSER".equals(existingUser.getRole())) {
                return "error: unauthorized to modify this user";
            }

            user.setRole("ENDUSER"); // Ensure role stays ENDUSER
            userService.updateUser(id, user);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @PostMapping("/user/delete/{id}")
    @ResponseBody
    public String deleteUser(@PathVariable Long id, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return "error: unauthorized";
            }

            // Admin can only delete ENDUSER
            User userToDelete = userService.getUserById(id)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (!"ENDUSER".equals(userToDelete.getRole())) {
                return "error: unauthorized to delete this user";
            }

            userService.deleteUser(id);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    @GetMapping("/sso-config")
    public String ssoConfig(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
            return "redirect:/login";
        }

        return "sso-config";
    }
}