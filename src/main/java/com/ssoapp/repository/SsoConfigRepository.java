package com.ssoapp.repository;

import com.ssoapp.model.SsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoConfigRepository extends JpaRepository<SsoConfig, Long> {
    List<SsoConfig> findByOrganizationId(Long organizationId);
    Optional<SsoConfig> findByOrganizationIdAndSsoTypeAndEnabledTrue(Long organizationId, String ssoType);
}