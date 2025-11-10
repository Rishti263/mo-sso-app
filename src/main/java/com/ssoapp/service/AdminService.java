package com.ssoapp.service;


import com.ssoapp.model.User;
import com.ssoapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;

    public List<User> getAllUsersForOrganization(Long organizationId) {
        return userRepository.findByOrganizationId(organizationId);
    }

    public List<User> getAllSuperadminUsers() {
        return userRepository.findByOrganizationIsNull();
    }
}
