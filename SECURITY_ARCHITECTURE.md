# Spring Security Boilerplate - Security Architecture

## Overview

This document describes the comprehensive security architecture of this Spring Security JWT boilerplate. It covers authentication, authorization, token management, and security mechanisms with detailed explanations of design decisions.

**Key Design Philosophy**: Balance security with performance - use short-lived stateless tokens for API access while maintaining security through server-side tracking where necessary.

---

## Architecture Components

### 1. Token Types & Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                        TOKEN LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐          ┌──────────────┐                     │
│  │  Access      │ 15 min  │  Refresh     │ 7 days              │
│  │  Token (JWT) │─────────▶│  Token (JWT) │                     │
│  │              │         │              │                     │
│  │ • Stateless  │         │ • DB tracked │                     │
│  │ • No DB hit  │         │ • Rotatable  │                     │
│  │ • Blacklist  │         │ • Revocable  │                     │
│  │   checked    │         │              │                     │
│  └──────────────┘         └──────────────┘                     │
│         │                          │                            │
│         ▼                          ▼                            │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │ In-Memory       │    │ Database        │                    │
│  │ Blacklist       │    │ (JTI tracking)  │                    │
│  │ (15 min max)    │    │ (7 day max)     │                    │
│  └─────────────────┘    └─────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Access Token (JWT)
- **Format**: Signed JWT (RS256)
- **Lifetime**: 15 minutes (configurable)
- **Storage**: Stateless - no server-side storage
- **Claims**:
  - `sub`: Username (human-readable identifier)
  - `userId`: Numeric user ID for database lookups
  - `jti`: Unique token ID for blacklisting
  - `scope`: User roles/permissions
  - `type`: "access"
  - `iat`, `exp`: Issued at and expiry times

**Why username in `sub`?** Spring Security's `authentication.getName()` returns the subject claim. Using username makes logs human-readable while the `userId` claim provides efficient database lookups.

#### Refresh Token (JWT + Database)
- **Format**: Signed JWT with server-side tracking
- **Lifetime**: 7 days (configurable)
- **Storage**: Database tracks JTI (JWT ID) with rotation state
- **Additional Claims**:
  - `tokenFamily`: UUID linking token rotation chain
  - `type`: "refresh"

**Why JWT for refresh tokens?** Provides signed, tamper-proof tokens that can be validated without database lookup, while the database tracking enables rotation and revocation.

---

### 2. Authentication Flow

```
┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│  Client │────▶│  /api/auth   │────▶│   DaoAuthentication   │
│         │     │   /login     │     │   Provider   │
└─────────┘     └──────────────┘     └──────────────┘     └──────────┘
                                              │
                                              ▼
                                       ┌──────────────┐
                                       │  UserDetails │
                                       │  Service     │
                                       └──────────────┘
                                              │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
             ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
             │  Access      │          │  Refresh     │          │  Store in    │
             │  Token       │          │  Token       │          │  Database    │
             │  (15 min)    │          │  (7 days)    │          │  (JTI +      │
             │              │          │              │          │  family)     │
             └──────────────┘          └──────────────┘          └──────────────┘
                    │                          │                          │
                    └──────────────────────────┼──────────────────────────┘
                                               │
                                               ▼
                                         ┌──────────┐
                                         │  Return  │
                                         │  to      │
                                         │  Client  │
                                         └──────────┘
```

**Key Design Decisions**:

1. **Custom JwtService for Token Issuance**: While Spring Resource Server is designed for token validation (not issuance), we use a custom `JwtService` for a self-contained monolithic architecture. For microservices or strict OAuth2 compliance, replace with Spring Authorization Server.

2. **RSA Key Pair (RS256)**: Uses asymmetric signing. The private key signs tokens; the public key validates them. This allows the public key to be shared with other services if needed.

---

### 3. Token Validation Flow (Spring Resource Server)

```
┌─────────┐                    ┌─────────────────────────────────────────┐
│  Client │───────────────────▶│   Spring Resource Server                │
│         │  Authorization:    │   (OAuth2 JWT Configuration)            │
│         │  Bearer <token>   │                                          │
└─────────┘                    └─────────────────────────────────────────┘
                                              │
                                              ▼
                                       ┌──────────────┐
                                       │  Custom      │
                                       │  JwtDecoder  │
                                       └──────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
                    ▼                         ▼                         ▼
             ┌──────────┐            ┌──────────────┐          ┌──────────────┐
             │ Nimbus   │            │  Token       │          │  Spring      │
             │ JwtDecoder│           │  Blacklist   │          │  Security    │
             │          │            │  Check       │          │  Context     │
             │          │            │              │          │              │
             │ Validate │            │  If revoked  │          │  authentication
             │ signature│            │  → throw     │          │  .getName()  │
             │ expiry   │            │  BadJwtException      │  = username  │
             └──────────┘            └──────────────┘          └──────────────┘
```

**Custom JwtDecoder Integration** (`@SecurityConfig.java:62-76`):

```java
@Bean
public JwtDecoder jwtDecoder(RsaKeyProperties keys, TokenBlacklistService tokenBlacklistService) {
    NimbusJwtDecoder delegate = NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();

    return token -> {
        // Step 1: Standard JWT validation (signature, expiry)
        Jwt jwt = delegate.decode(token);
        
        // Step 2: Blacklist check (custom security layer)
        String tokenId = jwt.getId();
        if (tokenId != null && tokenBlacklistService.isBlacklisted(tokenId)) {
            throw new BadJwtException("Token has been revoked");
        }
        
        return jwt;
    };
}
```

**Why this approach?**
- Spring Resource Server validates tokens on every request
- We wrap the standard decoder to add blacklist checking
- Blacklisted tokens (from logout) are rejected immediately
- Valid tokens proceed with zero additional overhead

---

### 4. Token Blacklist (Deny-List) Architecture

#### Problem: Stateless JWT Cannot Be "Un-Signed"
JWTs are cryptographically signed. Once issued, they remain valid until expiry unless we maintain a deny-list.

#### Solution: Two-Tier Blacklist System

```
┌─────────────────────────────────────────────────────────────────┐
│                    TOKEN BLACKLIST ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Logout Request                                                 │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────┐                                           │
│   │ Extract jti     │                                           │
│   │ & expiry        │                                           │
│   └────────┬────────┘                                           │
│            │                                                      │
│            ▼                                                      │
│   ┌──────────────────────────┐                                   │
│   │  InMemoryTokenBlacklist  │                                   │
│   │  (ConcurrentHashMap)     │                                   │
│   │                          │                                   │
│   │  Map: jti ──▶ expiry    │                                   │
│   │                          │                                   │
│   │  • O(1) lookup           │                                   │
│   │  • TTL auto-cleanup       │                                   │
│   │  • Lazy + eager cleanup   │                                   │
│   └──────────────────────────┘                                   │
│            │                                                      │
│            │ Validation Request                                    │
│            ▼                                                      │
│   ┌──────────────────────────────────────┐                     │
│   │  isBlacklisted(jti)?                 │                     │
│   │                                      │                     │
│   │  1. Check if jti in map              │                     │
│   │  2. If expired → remove (cleanup)    │                     │
│   │  3. Return: true/false               │                     │
│   └──────────────────────────────────────┘                     │
│                                                                  │
│   Cleanup Strategies:                                            │
│   • Lazy: On lookup, remove expired entries                     │
│   • Eager: Scheduled task every 5 minutes                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation** (`@InMemoryTokenBlacklistService.java`):

```java
@Service
public class InMemoryTokenBlacklistService implements TokenBlacklistService {
    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();
    
    public void blacklistToken(String tokenId, Instant expiresAt) {
        // Only blacklist if not already expired
        if (Instant.now().isAfter(expiresAt)) return;
        blacklistedTokens.put(tokenId, expiresAt);
    }
    
    public boolean isBlacklisted(String tokenId) {
        Instant expiry = blacklistedTokens.get(tokenId);
        if (expiry == null) return false;
        
        // Lazy cleanup
        if (Instant.now().isAfter(expiry)) {
            blacklistedTokens.remove(tokenId);
            return false;
        }
        return true;
    }
    
    @Scheduled(fixedRate = 300000) // Every 5 minutes
    public int cleanupExpiredEntries() { /* ... */ }
}
```

**Trade-offs**:

| Aspect | In-Memory | Database | Redis |
|--------|------------|----------|-------|
| Lookup Speed | ~0.1ms | ~5-10ms | ~1ms |
| Survives Restart | ❌ No | ✅ Yes | ✅ Yes (with persistence) |
| Distributed | ❌ No | ✅ Yes | ✅ Yes |
| Complexity | Low | Medium | Medium |

**Current Choice**: In-memory for single-instance deployments. For production with multiple instances, replace with Redis implementation.

---

### 5. Refresh Token Rotation & Security

```
┌─────────────────────────────────────────────────────────────────┐
│                 REFRESH TOKEN ROTATION FLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Initial Login                                                   │
│       │                                                          │
│       ▼                                                          │
│  ┌──────────────┐                                               │
│  │ Token Family │                                               │
│  │ UUID: abc-123│                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────────┐                                           │
│  │ Refresh Token #1 │  Stored in DB:                             │
│  │ jti: rt-001      │  • jti: rt-001                             │
│  │ family: abc-123  │  • family: abc-123                         │
│  │ used: false      │  • used: false                             │
│  └────────┬─────────┘                                            │
│           │                                                      │
│           │  First Refresh Request                               │
│           ▼                                                      │
│  ┌──────────────────────────────────────┐                     │
│  │ 1. Validate JWT signature & expiry     │                     │
│  │ 2. Find JTI in database               │                     │
│  │ 3. Check: used=false, revoked=false   │                     │
│  │ 4. Check: device fingerprint matches │                     │
│  │ 5. Mark rt-001 as used=true          │                     │
│  │ 6. Create rt-002 in same family        │                     │
│  └──────────────────────────────────────┘                         │
│           │                                                      │
│           ▼                                                      │
│  ┌──────────────────┐                                           │
│  │ Refresh Token #2 │  Stored in DB:                             │
│  │ jti: rt-002      │  • jti: rt-002 (new)                       │
│  │ family: abc-123  │  • jti: rt-001 (used=true)                 │
│  │ used: false      │                                              │
│  └──────────────────┘                                              │
│                                                                  │
│  Security: If rt-001 is presented again → REVOKE ENTIRE FAMILY  │
│  (Detects token theft - attacker using stolen old token)        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Device Fingerprint** (`@RefreshTokenService.java:213-221`):

```java
private String generateDeviceFingerprint(HttpServletRequest request) {
    String components = extractUserAgent(request) + "|" + extractIpAddress(request);
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(components.getBytes(StandardCharsets.UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
}
```

**Fingerprint Check** (`@RefreshTokenService.java:124-130`):
- Compares stored fingerprint with current request
- Mismatch triggers: revoke token family + throw exception
- Prevents stolen refresh tokens from being used on different devices

---

### 6. Logout & Token Revocation

```
┌─────────────────────────────────────────────────────────────────┐
│                    LOGOUT ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  POST /api/auth/logout                                           │
│  Headers:                                                        │
│    Authorization: Bearer <access_token>                         │
│    X-Refresh-Token: <refresh_token> (optional)                  │
│                                                                  │
│  Flow:                                                           │
│    1. Extract username from authentication.getName()            │
│    2. Extract jti from access token → Add to blacklist           │
│    3. If refresh token provided → Mark as revoked in DB        │
│    4. If no refresh token → Revoke all user refresh tokens     │
│                                                                  │
│  POST /api/auth/logout-all                                       │
│  Headers: Authorization: Bearer <access_token>                  │
│                                                                  │
│  Flow:                                                           │
│    1. Extract username from authentication                     │
│    2. Look up user ID from database                             │
│    3. Revoke ALL refresh tokens for user                        │
│                                                                  │
│  Result:                                                         │
│    • Access token blacklisted (immediately invalid)            │
│    • Refresh tokens revoked (cannot be used for renewal)        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 7. Rate Limiting & Brute Force Protection

**RateLimitingFilter** (`@RateLimitingFilter.java`):

```
┌─────────────────────────────────────────────────────────────────┐
│                    RATE LIMITING FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scope: /api/auth/** endpoints only                              │
│                                                                  │
│  Client Identifier: IP + endpoint path                          │
│  (Respects X-Forwarded-For for proxied requests)               │
│                                                                  │
│  Limits:                                                         │
│    • 10 requests per minute per client                            │
│    • Exceeding → Block for 15 minutes                            │
│                                                                  │
│  Implementation:                                                 │
│    ConcurrentHashMap<String, RateLimitEntry>                    │
│                                                                  │
│  State per entry:                                               │
│    • requestCount (AtomicInteger)                                │
│    • windowStart (Instant) - 60 second sliding window          │
│    • blockExpiry (Instant) - when block ends                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 8. Security Headers

All auth responses include:

| Header | Value | Purpose |
|--------|-------|---------|
| `Cache-Control` | `no-store` | Prevent token caching |
| `Pragma` | `no-cache` | HTTP/1.0 compatibility |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |

---

### 9. Database Schema

```sql
-- Refresh token tracking
CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token_id VARCHAR(64) NOT NULL UNIQUE,  -- JWT ID (jti claim)
    user_id BIGINT NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    used BOOLEAN DEFAULT FALSE,            -- For rotation detection
    token_family VARCHAR(64) NOT NULL,     -- Rotation chain grouping
    ip_address VARCHAR(45),                -- Client IP
    user_agent VARCHAR(512),               -- Browser fingerprint
    device_fingerprint VARCHAR(64),        -- SHA-256 hash
    version BIGINT,                        -- Optimistic locking
    
    INDEX idx_token_id (token_id),
    INDEX idx_user_family (user_id, token_family)
);

-- Token blacklist (if using persistent storage instead of in-memory)
-- CREATE TABLE token_blacklist (
--     token_id VARCHAR(64) PRIMARY KEY,
--     expires_at TIMESTAMP NOT NULL,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     INDEX idx_expires (expires_at)
-- );
```

---

### 10. Configuration

```properties
# Access token (short-lived, stateless)
app.security.access-token.expiration-minutes=15

# Refresh token (long-lived, DB tracked)
app.security.refresh-token.expiration-days=7

# Security features
app.security.refresh-token.detect-reuse=true

# RSA key pair for JWT signing (RS256)
rsa.private-key=classpath:certs/private.pem
rsa.public-key=classpath:certs/public.pem
```

---

### 11. Threat Model & Mitigations

| Threat | Mitigation | Implementation |
|--------|-----------|----------------|
| **Token theft (access)** | Short expiry + blacklist | 15 min expiry, deny-list on logout |
| **Token theft (refresh)** | Rotation + family detection | Single-use, family revocation on reuse |
| **Cross-device token use** | Device fingerprinting | SHA-256 hash of UA+IP, blocks on mismatch |
| **Replay attacks** | Token rotation | New refresh token on every use |
| **Brute force login** | Rate limiting | 10 req/min, 15 min block |
| **Token caching** | Security headers | Cache-Control: no-store |
| **Stolen token from memory** | Short-lived tokens | Minimizes window of abuse |
| **Database breach** | No raw tokens stored | Only JTI (token IDs) stored, not full tokens |
| **Privilege escalation** | Scope validation | JWT contains roles, validated on each request |

---

### 12. Deployment Considerations

#### Single Instance (Current)
- ✅ In-memory blacklist sufficient
- ✅ Simple deployment
- ⚠️ Restart clears blacklist (15 min max exposure)

#### Multiple Instances / Production
- **Redis for blacklist**: Shared across instances, survives restart
- **Database for refresh tokens**: Already implemented
- **Load balancer sticky sessions**: Optional, for consistent device fingerprinting

---

### 13. API Endpoints Summary

| Endpoint | Auth | Request | Response |
|----------|------|---------|----------|
| `POST /api/auth/login` | None | `{"username":"","password":""}` | Access + Refresh tokens |
| `POST /api/auth/refresh` | None | `{"refreshToken":""}` | New Access + Refresh tokens |
| `POST /api/auth/logout` | Bearer | `X-Refresh-Token` (opt) | Success/Error |
| `POST /api/auth/logout-all` | Bearer | None | Success/Error |

---

## Compliance & Standards

This implementation follows:
- **OWASP JWT Security Cheat Sheet**
- **OAuth 2.0 Best Current Practice (BCP)**
- **NIST Digital Identity Guidelines (SP 800-63)**
- **PCI DSS session management** (for applicable deployments)

---

## Migration Guide: To Spring Authorization Server

If you need strict OAuth2/OIDC compliance:

1. Add dependency: `spring-authorization-server`
2. Remove `JwtService.generateAccessToken()` and `generateRefreshToken()`
3. Configure `RegisteredClientRepository` for client registration
4. Move login logic to Authorization Server
5. This app becomes pure Resource Server (token validation only)

Current architecture is optimized for **self-contained monoliths**. Choose based on your deployment needs.
