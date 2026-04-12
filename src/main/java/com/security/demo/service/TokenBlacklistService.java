package com.security.demo.service;

import java.time.Instant;

/**
 * Service for managing revoked/blacklisted JWT tokens.
 * <p>
 * Since JWTs are stateless and cannot be "un-signed", this service maintains
 * a deny-list of token IDs (jti claim) that should be rejected even if
 * the signature is valid and the token hasn't expired.
 * <p>
 * Tokens are stored with their expiry time, allowing automatic cleanup
 * of expired entries.
 */
public interface TokenBlacklistService {

    /**
     * Add a token ID to the blacklist.
     *
     * @param tokenId   the JWT ID (jti claim)
     * @param expiresAt when the token naturally expires (for TTL calculation)
     */
    void blacklistToken(String tokenId, Instant expiresAt);

    /**
     * Check if a token ID is blacklisted.
     *
     * @param tokenId the JWT ID (jti claim)
     * @return true if the token is blacklisted and should be rejected
     */
    boolean isBlacklisted(String tokenId);

    /**
     * Clean up expired entries from the blacklist.
     * Called periodically by scheduled tasks.
     *
     * @return number of entries removed
     */
    int cleanupExpiredEntries();
}
