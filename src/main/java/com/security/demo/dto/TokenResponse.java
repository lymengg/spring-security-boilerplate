package com.security.demo.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn,
        @JsonProperty("access_token_expires_at") Instant accessTokenExpiresAt
) {}
