package com.security.demo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final int BLOCK_DURATION_MINUTES = 15;

    private final Map<String, RateLimitEntry> rateLimits = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        if (!path.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientId = getClientIdentifier(request);
        RateLimitEntry entry = rateLimits.computeIfAbsent(clientId, k -> new RateLimitEntry());

        synchronized (entry) {
            Instant now = Instant.now();

            if (entry.isBlocked(now)) {
                long remainingSeconds = entry.getBlockExpiry().getEpochSecond() - now.getEpochSecond();
                log.warn("Rate limit exceeded for client: {}, path: {}", clientId, path);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                        "{\"code\":429,\"message\":\"Rate limit exceeded. Try again in %d seconds\",\"data\":null}",
                        remainingSeconds
                ));
                return;
            }

            entry.recordRequest(now);

            if (entry.shouldBlock()) {
                entry.block(now.plusSeconds(BLOCK_DURATION_MINUTES * 60));
                log.warn("Client blocked due to rate limit: {}, path: {}", clientId, path);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                        "{\"code\":429,\"message\":\"Too many requests. Blocked for %d minutes\",\"data\":null}",
                        BLOCK_DURATION_MINUTES
                ));
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIdentifier(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim() + ":" + request.getRequestURI();
        }
        return request.getRemoteAddr() + ":" + request.getRequestURI();
    }

    private static class RateLimitEntry {
        private final AtomicInteger requestCount = new AtomicInteger(0);
        private Instant windowStart = Instant.now();
        private Instant blockExpiry = null;

        synchronized void recordRequest(Instant now) {
            if (now.isAfter(windowStart.plusSeconds(60))) {
                windowStart = now;
                requestCount.set(0);
            }
            requestCount.incrementAndGet();
        }

        synchronized boolean shouldBlock() {
            return requestCount.get() > MAX_REQUESTS_PER_MINUTE;
        }

        synchronized void block(Instant expiry) {
            this.blockExpiry = expiry;
        }

        synchronized boolean isBlocked(Instant now) {
            if (blockExpiry == null) {
                return false;
            }
            if (now.isAfter(blockExpiry)) {
                blockExpiry = null;
                requestCount.set(0);
                windowStart = now;
                return false;
            }
            return true;
        }

        synchronized Instant getBlockExpiry() {
            return blockExpiry;
        }
    }
}
