package com.ssoapp.repository;

import com.ssoapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsernameAndOrganizationId(String username, Long organizationId);
    Optional<User> findByUsernameAndOrganizationIsNull(String username);
    boolean existsByUsernameAndOrganizationIsNull(String username);
    boolean existsByUsernameAndOrganizationId(String username, Long organizationId);
    List<User> findByOrganizationId(Long organizationId);
    List<User> findByOrganizationIsNull();
}