package com.security.demo.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private String roles;

    @Builder.Default
    private boolean enabled = true;

    @Builder.Default
    private boolean locked = false;

    @Builder.Default
    private int failedAttempts = 0; // New field for the service below

    private LocalDateTime expiresAt;

    private LocalDateTime pwdExpiresAt;

    // Keep these helper methods for the wrapper to use
    public boolean isAccountActive() {
        return expiresAt == null || expiresAt.isAfter(LocalDateTime.now());
    }

    public boolean isPasswordValid() {
        return pwdExpiresAt == null || pwdExpiresAt.isAfter(LocalDateTime.now());
    }

    // Logic for the Login Attempt Service
    public void incrementFailedAttempts() {
        this.failedAttempts++;
        if (this.failedAttempts >= 5) {
            this.locked = true;
        }
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.locked = false;
    }
}
