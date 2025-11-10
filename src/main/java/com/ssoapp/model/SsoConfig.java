package com.ssoapp.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "sso_configs")
@Data
public class SsoConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;

    @Column(nullable = false)
    private String ssoType; // SAML, OAUTH, MINIORANGE

    @Column(nullable = false)
    private boolean enabled;

    // SAML Configuration
    @Column(length = 2000)
    private String idpEntityId;

    @Column(length = 2000)
    private String idpSsoUrl;

    @Column(length = 2000)
    private String idpSloUrl;

    @Column(length = 5000)
    private String idpCertificate;

    // OAuth Configuration
    @Column(length = 500)
    private String clientId;

    @Column(length = 500)
    private String clientSecret;

    @Column(length = 2000)
    private String authorizationUri;

    @Column(length = 2000)
    private String tokenUri;

    @Column(length = 2000)
    private String userInfoUri;

    // MiniOrange Configuration
    @Column(length = 5000)
    private String miniOrangePublicKey;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}