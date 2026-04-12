package com.security.demo.repository;

import com.security.demo.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenId(String tokenId);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.tokenFamily = :family AND rt.revoked = false")
    List<RefreshToken> findActiveTokensByUserAndFamily(@Param("userId") Long userId, @Param("family") String family);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.used = false AND rt.revoked = false AND rt.expiryDate > :now")
    List<RefreshToken> findValidTokensByUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userId = :userId")
    void revokeAllUserTokens(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.userId = :userId AND rt.tokenFamily = :family")
    void revokeTokenFamily(@Param("userId") Long userId, @Param("family") String family);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now OR rt.revoked = true")
    int deleteExpiredOrRevokedTokens(@Param("now") Instant now);

    boolean existsByTokenIdAndUserId(String tokenId, Long userId);
}
