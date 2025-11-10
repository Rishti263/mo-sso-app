package com.ssoapp.repository;


import com.ssoapp.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OrganizationRepository extends JpaRepository<Organization, Long> {
    Optional<Organization> findBySubdomain(String subdomain);
    boolean existsBySubdomain(String subdomain);
}
