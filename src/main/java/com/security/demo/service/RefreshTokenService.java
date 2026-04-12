package com.security.demo.service;

import com.security.demo.entity.RefreshToken;
import com.security.demo.entity.User;
import com.security.demo.repository.RefreshTokenRepository;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.exception.TokenRefreshException;
import com.security.demo.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${app.security.refresh-token.detect-reuse:true}")
    private boolean detectReuse;

    @Transactional
    public RefreshTokenResult createRefreshToken(Long userId, HttpServletRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new TokenRefreshException("User not found"));

        String tokenFamily = UUID.randomUUID().toString();

        // Generate JWT refresh token - returns both token and ID without decoding
        JwtService.TokenWithId tokenWithId = jwtService.generateRefreshToken(user, tokenFamily);
        String tokenValue = tokenWithId.token();
        String tokenId = tokenWithId.tokenId();

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(tokenId)
                .userId(userId)
                .tokenFamily(tokenFamily)
                .expiryDate(jwtService.getRefreshTokenExpiration())
                .ipAddress(extractIpAddress(request))
                .userAgent(extractUserAgent(request))
                .deviceFingerprint(generateDeviceFingerprint(request))
                .build();

        refreshTokenRepository.save(refreshToken);

        log.info("Created JWT refresh token for user: {}, family: {}, jti: {}", userId, tokenFamily, tokenId);

        return new RefreshTokenResult(tokenValue, refreshToken);
    }

    @Transactional
    public RefreshTokenRotationResult rotateRefreshToken(String rawRefreshToken, HttpServletRequest request) {
        // Validate JWT refresh token
        JwtService.RefreshTokenDetails tokenDetails = jwtService.validateAndParseRefreshToken(rawRefreshToken);
        String tokenId = tokenDetails.tokenId();

        RefreshToken currentToken = refreshTokenRepository.findByTokenId(tokenId)
                .orElseThrow(() -> {
                    log.warn("JWT refresh token JTI not found in database - possible attack or expired token");
                    return new TokenRefreshException("Invalid refresh token");
                });

        // Additional validation: ensure JTI from JWT matches stored token
        if (!currentToken.getTokenId().equals(tokenId)) {
            log.error("SECURITY ALERT: Token ID mismatch - possible token forgery");
            throw new TokenRefreshException("Invalid refresh token");
        }

        if (currentToken.isUsed()) {
            log.error("SECURITY ALERT: Refresh token reuse detected for user: {}, family: {}, jti: {}",
                    currentToken.getUserId(), currentToken.getTokenFamily(), tokenId);

            revokeTokenFamily(currentToken.getUserId(), currentToken.getTokenFamily());
            throw new TokenRefreshException("Token reuse detected. All tokens in this family have been revoked.");
        }

        if (currentToken.isRevoked()) {
            log.warn("Attempt to use revoked refresh token for user: {}", currentToken.getUserId());
            throw new TokenRefreshException("Refresh token has been revoked");
        }

        if (currentToken.isExpired()) {
            log.info("Expired refresh token used for user: {}", currentToken.getUserId());
            throw new TokenRefreshException("Refresh token has expired");
        }

        User user = userRepository.findById(currentToken.getUserId())
                .orElseThrow(() -> new TokenRefreshException("User not found"));

        if (!user.isEnabled() || user.isLocked()) {
            log.warn("Attempt to refresh token for disabled/locked user: {}", user.getId());
            throw new TokenRefreshException("User account is disabled or locked");
        }

        if (detectReuse) {
            List<RefreshToken> activeTokens = refreshTokenRepository
                    .findActiveTokensByUserAndFamily(currentToken.getUserId(), currentToken.getTokenFamily());

            long unusedTokens = activeTokens.stream()
                    .filter(t -> !t.getId().equals(currentToken.getId()) && !t.isUsed() && !t.isRevoked())
                    .count();

            if (unusedTokens > 0) {
                log.error("SECURITY ALERT: Token family {} has {} unused siblings - possible token theft",
                        currentToken.getTokenFamily(), unusedTokens);
            }
        }

        String deviceFingerprint = generateDeviceFingerprint(request);
        if (currentToken.getDeviceFingerprint() != null &&
                !currentToken.getDeviceFingerprint().equals(deviceFingerprint)) {
            log.error("SECURITY ALERT: Device fingerprint mismatch for user: {}. Token theft suspected. Revoking token family.",
                    currentToken.getUserId());
            revokeTokenFamily(currentToken.getUserId(), currentToken.getTokenFamily());
            throw new TokenRefreshException("Token used from unrecognized device. Please login again.");
        }

        // Mark current token as used
        currentToken.setUsed(true);
        refreshTokenRepository.save(currentToken);

        // Generate new JWT refresh token in the same family - returns both token and ID
        JwtService.TokenWithId newTokenWithId = jwtService.generateRefreshToken(user, currentToken.getTokenFamily());
        String newTokenValue = newTokenWithId.token();
        String newTokenId = newTokenWithId.tokenId();

        RefreshToken newRefreshToken = RefreshToken.builder()
                .tokenId(newTokenId)
                .userId(currentToken.getUserId())
                .tokenFamily(currentToken.getTokenFamily())
                .expiryDate(jwtService.getRefreshTokenExpiration())
                .ipAddress(extractIpAddress(request))
                .userAgent(extractUserAgent(request))
                .deviceFingerprint(deviceFingerprint)
                .build();

        refreshTokenRepository.save(newRefreshToken);

        log.info("Rotated JWT refresh token for user: {}, family: {}, new jti: {}",
                currentToken.getUserId(), currentToken.getTokenFamily(), newTokenId);

        return new RefreshTokenRotationResult(newTokenValue, newRefreshToken, currentToken.getUserId());
    }

    @Transactional
    public void revokeUserTokens(Long userId) {
        refreshTokenRepository.revokeAllUserTokens(userId);
        log.info("Revoked all refresh tokens for user: {}", userId);
    }

    @Transactional
    public void revokeTokenFamily(Long userId, String tokenFamily) {
        refreshTokenRepository.revokeTokenFamily(userId, tokenFamily);
        log.warn("Revoked entire token family: {} for user: {}", tokenFamily, userId);
    }

    @Transactional
    public void revokeSingleToken(String rawRefreshToken) {
        try {
            // Validate and extract JTI from the JWT - ensures signature is valid before revocation
            JwtService.RefreshTokenDetails details = jwtService.validateAndParseRefreshToken(rawRefreshToken);
            String tokenId = details.tokenId();

            refreshTokenRepository.findByTokenId(tokenId).ifPresent(token -> {
                token.setRevoked(true);
                refreshTokenRepository.save(token);
                log.info("Revoked single JWT refresh token for user: {}, jti: {}", token.getUserId(), tokenId);
            });
        } catch (JwtService.JwtValidationException e) {
            log.warn("Could not revoke token - invalid JWT: {}", e.getMessage());
        }
    }

    @Transactional
    public int cleanupExpiredTokens() {
        Instant now = Instant.now();
        int deletedCount = refreshTokenRepository.deleteExpiredOrRevokedTokens(now);
        log.info("Cleaned up {} expired/revoked refresh tokens", deletedCount);
        return deletedCount;
    }

    private String extractIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    private String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent.substring(0, Math.min(userAgent.length(), 512)) : "unknown";
    }

    private String generateDeviceFingerprint(HttpServletRequest request) {
        String components = extractUserAgent(request) + "|" + extractIpAddress(request);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(components.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return "unknown";
        }
    }

    public record RefreshTokenResult(String rawToken, RefreshToken entity) {
    }

    public record RefreshTokenRotationResult(String rawToken, RefreshToken entity, Long userId) {
    }
}
