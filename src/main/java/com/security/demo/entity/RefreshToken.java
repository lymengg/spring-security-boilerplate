package com.security.demo.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_token_id", columnList = "tokenId"),
        @Index(name = "idx_user_family", columnList = "userId,tokenFamily")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64, unique = true)
    private String tokenId;  // JWT ID (jti claim)

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private Instant createdAt;

    @Builder.Default
    private boolean revoked = false;

    @Builder.Default
    private boolean used = false;

    @Column(nullable = false, length = 64)
    private String tokenFamily;

    private String ipAddress;

    private String userAgent;

    private String deviceFingerprint;

    @Version
    private Long version;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiryDate);
    }

    public boolean isValid() {
        return !revoked && !used && !isExpired();
    }
}
