package com.security.demo.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenRefreshResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long expiresIn,
        Instant accessTokenExpiresAt,
        Boolean rotationDetected,
        String securityMessage
) {}
