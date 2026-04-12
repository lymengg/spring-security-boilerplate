package com.security.demo.security.jwt;

import com.security.demo.entity.User;
import com.security.demo.service.TokenBlacklistService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtEncoder encoder;
    private final JwtDecoder decoder;
    private final TokenBlacklistService tokenBlacklistService;

    @Value("${app.security.access-token.expiration-minutes:15}")
    private long accessTokenExpirationMinutes;

    @Value("${app.security.refresh-token.expiration-days:7}")
    private long refreshTokenExpirationDays;

    public JwtService(JwtEncoder encoder, JwtDecoder decoder, TokenBlacklistService tokenBlacklistService) {
        this.encoder = encoder;
        this.decoder = decoder;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES))
                .subject(user.getUsername())
                .id(UUID.randomUUID().toString())
                .claim("userId", user.getId())
                .claim("scope", user.getRoles())
                .claim("type", "access")
                .build();

        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public AccessTokenDetails validateAndParseAccessToken(String token) {
        try {
            Jwt jwt = decoder.decode(token);

            String tokenType = jwt.getClaimAsString("type");
            if (!"access".equals(tokenType)) {
                throw new JwtValidationException("Invalid token type");
            }

            // Check if token has been blacklisted (revoked via logout)
            String tokenId = jwt.getId();
            if (tokenId != null && tokenBlacklistService.isBlacklisted(tokenId)) {
                throw new JwtValidationException("Token has been revoked");
            }

            Instant expiry = jwt.getExpiresAt();
            if (expiry == null || Instant.now().isAfter(expiry)) {
                throw new JwtValidationException("Token has expired");
            }

            return new AccessTokenDetails(
                    jwt.getSubject(),
                    jwt.getClaimAsString("scope"),
                    jwt.getClaim("userId"),
                    tokenId,
                    expiry
            );
        } catch (JwtException e) {
            throw new JwtValidationException("Invalid token: " + e.getMessage(), e);
        }
    }

    public Optional<String> extractUsername(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            return Optional.ofNullable(jwt.getSubject());
        } catch (JwtException e) {
            return Optional.empty();
        }
    }

    public TokenWithId generateRefreshToken(User user, String tokenFamily) {
        Instant now = Instant.now();
        String tokenId = UUID.randomUUID().toString();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(refreshTokenExpirationDays, ChronoUnit.DAYS))
                .subject(user.getUsername())
                .id(tokenId)
                .claim("userId", user.getId())
                .claim("scope", user.getRoles())
                .claim("type", "refresh")
                .claim("tokenFamily", tokenFamily)
                .build();

        String token = this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return new TokenWithId(token, tokenId);
    }

    public record TokenWithId(String token, String tokenId) {}

    public RefreshTokenDetails validateAndParseRefreshToken(String token) {
        try {
            Jwt jwt = decoder.decode(token);

            String tokenType = jwt.getClaimAsString("type");
            if (!"refresh".equals(tokenType)) {
                throw new JwtValidationException("Invalid token type");
            }

            Instant expiry = jwt.getExpiresAt();
            if (expiry == null || Instant.now().isAfter(expiry)) {
                throw new JwtValidationException("Token has expired");
            }

            return new RefreshTokenDetails(
                    jwt.getSubject(),
                    jwt.getClaimAsString("scope"),
                    jwt.getClaim("userId"),
                    jwt.getId(),
                    expiry,
                    jwt.getClaimAsString("tokenFamily")
            );
        } catch (JwtException e) {
            throw new JwtValidationException("Invalid token: " + e.getMessage(), e);
        }
    }

    public String extractTokenId(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            return jwt.getId();
        } catch (JwtException e) {
            return null;
        }
    }

    /**
     * Extract token ID and expiry for blacklisting purposes.
     * This does not validate the token, only decodes it.
     *
     * @param token the JWT string
     * @return TokenIdWithExpiry or null if token is invalid
     */
    public TokenIdWithExpiry extractTokenIdAndExpiry(String token) {
        try {
            Jwt jwt = decoder.decode(token);
            String tokenType = jwt.getClaimAsString("type");
            // Only extract from access tokens
            if (!"access".equals(tokenType)) {
                return null;
            }
            return new TokenIdWithExpiry(jwt.getId(), jwt.getExpiresAt());
        } catch (JwtException e) {
            return null;
        }
    }

    public record TokenIdWithExpiry(String tokenId, Instant expiresAt) {}

    public Instant getAccessTokenExpiration() {
        return Instant.now().plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES);
    }

    public long getAccessTokenExpirationMinutes() {
        return accessTokenExpirationMinutes;
    }

    public long getRefreshTokenExpirationDays() {
        return refreshTokenExpirationDays;
    }

    public Instant getRefreshTokenExpiration() {
        return Instant.now().plus(refreshTokenExpirationDays, ChronoUnit.DAYS);
    }

    public record AccessTokenDetails(
            String username,
            String scope,
            Long userId,
            String tokenId,
            Instant expiresAt
    ) {}

    public record RefreshTokenDetails(
            String username,
            String scope,
            Long userId,
            String tokenId,
            Instant expiresAt,
            String tokenFamily
    ) {}

    public static class JwtValidationException extends RuntimeException {
        public JwtValidationException(String message) {
            super(message);
        }
        public JwtValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
