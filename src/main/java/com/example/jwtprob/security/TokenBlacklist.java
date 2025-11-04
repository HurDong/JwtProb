package com.example.jwtprob.security;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "token_blacklist", indexes = {
        @Index(name = "idx_token", columnList = "token"),
        @Index(name = "idx_expiration", columnList = "expiration")
})
public class TokenBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 500, nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiration;

    @Column(nullable = false)
    private LocalDateTime blacklistedAt;

    private String reason; // "LOGOUT", "SECURITY_ISSUE" 등

    protected TokenBlacklist() {
    }

    public TokenBlacklist(String token, LocalDateTime expiration, String reason) {
        this.token = token;
        this.expiration = expiration;
        this.blacklistedAt = LocalDateTime.now();
        this.reason = reason;
    }

    public Long getId() {
        return id;
    }

    public String getToken() {
        return token;
    }

    public LocalDateTime getExpiration() {
        return expiration;
    }

    public LocalDateTime getBlacklistedAt() {
        return blacklistedAt;
    }

    public String getReason() {
        return reason;
    }
}

