# Refresh Token Security Implementation

## Overview
This document describes the secure refresh token implementation following OWASP guidelines and industry best practices.

## Security Features Implemented

### 1. Token Structure
- **Access Tokens**: Short-lived (15 minutes by default), stateless JWT
- **Refresh Tokens**: Long-lived (7 days by default), JWT format with server-side rotation tracking

### 2. Refresh Token Security

#### JWT Format with Server-Side Tracking
- Refresh tokens are **signed JWTs** (same format as access tokens)
- JWT claims include: `userId`, `scope`, `type=refresh`, `tokenFamily`, `jti` (token ID)
- Database stores the **JTI (JWT ID)** to track token rotation and detect reuse
- Indexed database queries for efficient lookups by JTI

#### Token Rotation
- Every refresh token use generates a **new refresh token**
- Previous token is marked as **used** and cannot be reused
- Prevents replay attacks and enables theft detection

#### Token Family Detection
- Each refresh token JWT contains a `tokenFamily` claim (chain of rotations)
- Database tracks JTI usage status for each token
- If a **used token is presented again**, entire family is revoked
- This detects token theft scenarios where attacker steals and uses old token

#### Device Fingerprinting
- Tokens are bound to device characteristics (IP + User-Agent hash)
- Fingerprint mismatch triggers security logging (optional blocking)

### 3. Rate Limiting
- In-memory rate limiting on all `/api/auth/**` endpoints
- Limits: 10 requests per minute per IP+endpoint
- Auto-blocking: 15 minutes after exceeding limits

### 4. Security Headers
All auth endpoints return:
- `Cache-Control: no-store`
- `Pragma: no-cache`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

### 5. Token Revocation
- **Logout**: Revokes single refresh token
- **Logout All**: Revokes all user tokens (all devices)
- **Auto-cleanup**: Scheduled job removes expired/revoked tokens daily

## API Endpoints

### POST /api/auth/login
**Request:**
```json
{
  "username": "user",
  "password": "pass"
}
```

**Response:**
```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "accessToken": "eyJhbG...",
    "refreshToken": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "access_token_expires_at": "2026-04-11T07:45:00Z"
  }
}
```

### POST /api/auth/refresh
**Request:**
```json
{
  "refreshToken": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."
}
```

**Response:**
```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "accessToken": "eyJhbG...",
    "refreshToken": "bmV3IHJlZnJlc2ggdG9rZW4...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "accessTokenExpiresAt": "2026-04-11T07:45:00Z"
  }
}
```

### POST /api/auth/logout
**Headers:**
- `X-Refresh-Token: <refresh_token>` (optional)
- `Authorization: Bearer <access_token>` (optional)

Revokes the provided refresh token or all tokens for authenticated user.

### POST /api/auth/logout-all
**Headers:**
- `Authorization: Bearer <access_token>`

Revokes all refresh tokens for the authenticated user (logout from all devices).

## Configuration

```properties
# Access token expiration (minutes)
app.security.access-token.expiration-minutes=15

# Refresh token expiration (days)
app.security.refresh-token.expiration-days=7

# Enable reuse detection (token theft detection)
app.security.refresh-token.detect-reuse=true
```

## Database Schema

```sql
CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token_id VARCHAR(64) NOT NULL UNIQUE,  -- JWT ID (jti claim)
    user_id BIGINT NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    used BOOLEAN DEFAULT FALSE,
    token_family VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    device_fingerprint VARCHAR(64),
    version BIGINT,
    INDEX idx_token_id (token_id),
    INDEX idx_user_family (user_id, token_family)
);
```

## Security Threat Mitigations

| Threat | Mitigation |
|--------|-----------|
| Token theft | Token rotation + family detection |
| Replay attacks | Single-use refresh tokens |
| Database breach | SHA-256 hashing of tokens |
| Brute force | Rate limiting per IP |
| XSS token theft | Short-lived access tokens |
| Token enumeration | Cryptographically random tokens (256-bit) |
| Session fixation | New token family on each login |

## Penetration Testing Checklist

- [ ] Attempt to reuse a refresh token (should fail, family revoked)
- [ ] Attempt refresh with invalid token (should return 401)
- [ ] Attempt refresh with expired token (should return 401)
- [ ] Attempt login with rate limit exceeded (should return 429)
- [ ] Verify access tokens expire correctly (short-lived)
- [ ] Verify refresh tokens can be revoked
- [ ] Verify logout from all devices works
- [ ] Check for token in response headers (should not be cacheable)
- [ ] Attempt CSRF on auth endpoints (should fail with 401/403)
- [ ] Verify SQL injection protection in token lookups

## Compliance

This implementation follows:
- OWASP JWT Security Cheat Sheet
- OAuth 2.0 Best Current Practice (BCP)
- NIST Digital Identity Guidelines (SP 800-63)
- PCI DSS session management requirements
