package com.security.demo.scheduled;

import com.security.demo.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupTask {

    private final RefreshTokenService refreshTokenService;

    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupExpiredTokens() {
        log.info("Starting scheduled cleanup of expired refresh tokens");
        int deletedCount = refreshTokenService.cleanupExpiredTokens();
        log.info("Completed scheduled cleanup - deleted {} expired/revoked refresh tokens", deletedCount);
    }
}
