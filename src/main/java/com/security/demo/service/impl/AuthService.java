package com.security.demo.service.impl;

import com.security.demo.dto.LoginRequest;
import com.security.demo.dto.RefreshTokenRequest;
import com.security.demo.dto.TokenRefreshResponse;
import com.security.demo.dto.TokenResponse;
import com.security.demo.entity.User;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.jwt.JwtService;
import com.security.demo.service.RefreshTokenService;
import com.security.demo.service.TokenBlacklistService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;

    @Transactional
    public TokenResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(), request.password()
                )
        );

        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        String accessToken = jwtService.generateAccessToken(user);

        RefreshTokenService.RefreshTokenResult refreshResult = refreshTokenService
                .createRefreshToken(user.getId(), httpRequest);

        log.info("User {} logged in successfully", user.getUsername());

        return new TokenResponse(
                accessToken,
                refreshResult.rawToken(),
                "Bearer",
                jwtService.getAccessTokenExpirationMinutes() * 60,
                jwtService.getAccessTokenExpiration()
        );
    }

    @Transactional
    public TokenRefreshResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpRequest) {
        RefreshTokenService.RefreshTokenRotationResult rotationResult = refreshTokenService
                .rotateRefreshToken(request.refreshToken(), httpRequest);

        User user = userRepository.findById(rotationResult.userId())
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(user);

        log.info("Token refreshed for user: {}", user.getUsername());

        return new TokenRefreshResponse(
                newAccessToken,
                rotationResult.rawToken(),
                "Bearer",
                jwtService.getAccessTokenExpirationMinutes() * 60,
                jwtService.getAccessTokenExpiration(),
                null,
                null
        );
    }

    @Transactional
    public void logout(String accessToken, String refreshToken, String username) {
        Long userId = null;
        if (username != null) {
            userId = userRepository.findByUsername(username)
                    .map(User::getId)
                    .orElse(null);
        }

        // Blacklist the access token for immediate invalidation
        if (accessToken != null && !accessToken.isEmpty()) {
            JwtService.TokenIdWithExpiry tokenInfo = jwtService.extractTokenIdAndExpiry(accessToken);
            if (tokenInfo != null && tokenInfo.tokenId() != null) {
                tokenBlacklistService.blacklistToken(tokenInfo.tokenId(), tokenInfo.expiresAt());
                log.info("Blacklisted access token {} for user {}", tokenInfo.tokenId(), username);
            }
        }

        // Revoke the refresh token
        if (refreshToken != null && !refreshToken.isEmpty()) {
            refreshTokenService.revokeSingleToken(refreshToken);
        } else if (userId != null) {
            refreshTokenService.revokeUserTokens(userId);
        }

        log.info("User {} logged out", username);
    }

    @Transactional
    public void logoutAllDevices(String username) {
        userRepository.findByUsername(username).ifPresentOrElse(
                user -> {
                    refreshTokenService.revokeUserTokens(user.getId());
                    log.info("User {} logged out from all devices", username);
                },
                () -> log.warn("User {} not found for logout-all", username)
        );
    }
}
