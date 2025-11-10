package com.ssoapp.service;

import com.ssoapp.model.SsoConfig;
import com.ssoapp.repository.SsoConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SsoConfigService {

    private final SsoConfigRepository ssoConfigRepository;

    public List<SsoConfig> getConfigsByOrganizationId(Long organizationId) {
        return ssoConfigRepository.findByOrganizationId(organizationId);
    }

    public Optional<SsoConfig> getEnabledConfig(Long organizationId, String ssoType) {
        return ssoConfigRepository.findByOrganizationIdAndSsoTypeAndEnabledTrue(organizationId, ssoType);
    }

    public SsoConfig saveConfig(SsoConfig config) {
        return ssoConfigRepository.save(config);
    }
}