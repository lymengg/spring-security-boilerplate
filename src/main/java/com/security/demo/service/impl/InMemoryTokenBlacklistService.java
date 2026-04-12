package com.security.demo.service.impl;

import com.security.demo.service.TokenBlacklistService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of TokenBlacklistService using ConcurrentHashMap.
 * <p>
 * This implementation is suitable for single-instance deployments.
 * For distributed/multi-instance deployments, replace with Redis-backed implementation.
 * <p>
 * Entries are automatically cleaned up via:
 * 1. TTL checks on isBlacklisted() calls (lazy cleanup)
 * 2. Scheduled cleanup task (eager cleanup)
 */
@Service
@Slf4j
public class InMemoryTokenBlacklistService implements TokenBlacklistService {

    // Map: tokenId -> expiry time
    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();

    @Override
    public void blacklistToken(String tokenId, Instant expiresAt) {
        if (tokenId == null || expiresAt == null) {
            log.warn("Cannot blacklist token with null ID or expiry");
            return;
        }

        // Only blacklist if token hasn't already expired
        if (Instant.now().isAfter(expiresAt)) {
            log.debug("Token {} already expired, skipping blacklist", tokenId);
            return;
        }

        blacklistedTokens.put(tokenId, expiresAt);
        log.info("Blacklisted token {} (expires at {})", tokenId, expiresAt);
    }

    @Override
    public boolean isBlacklisted(String tokenId) {
        if (tokenId == null) {
            return false;
        }

        Instant expiry = blacklistedTokens.get(tokenId);

        // Token not in blacklist
        if (expiry == null) {
            return false;
        }

        // Lazy cleanup: if expired, remove and return not blacklisted
        if (Instant.now().isAfter(expiry)) {
            blacklistedTokens.remove(tokenId);
            log.debug("Lazy cleanup: removed expired token {} from blacklist", tokenId);
            return false;
        }

        return true;
    }

    @Override
    @Scheduled(fixedRate = 300000) // Every 5 minutes
    public int cleanupExpiredEntries() {
        Instant now = Instant.now();
        int removed = 0;

        for (Map.Entry<String, Instant> entry : blacklistedTokens.entrySet()) {
            if (now.isAfter(entry.getValue())) {
                blacklistedTokens.remove(entry.getKey());
                removed++;
            }
        }

        if (removed > 0) {
            log.info("Cleaned up {} expired tokens from blacklist", removed);
        }

        return removed;
    }
}
