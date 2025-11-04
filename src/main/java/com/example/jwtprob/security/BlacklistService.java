package com.example.jwtprob.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Service
public class BlacklistService {

    private static final Logger log = LoggerFactory.getLogger(BlacklistService.class);

    private final TokenBlacklistRepository blacklistRepository;
    private final JwtProperties jwtProperties;
    private final Key key;

    public BlacklistService(TokenBlacklistRepository blacklistRepository, JwtProperties jwtProperties) {
        this.blacklistRepository = blacklistRepository;
        this.jwtProperties = jwtProperties;
        byte[] keyBytes = Decoders.BASE64.decode(ensureBase64(jwtProperties.getSecret()));
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    @Transactional
    public void addToBlacklist(String token, String reason) {
        if (blacklistRepository.existsByToken(token)) {
            log.warn("토큰이 이미 블랙리스트에 존재합니다: token length={}", token.length());
            return;
        }

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Date expiration = claims.getExpiration();
            LocalDateTime expirationDateTime = expiration.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();

            TokenBlacklist blacklist = new TokenBlacklist(token, expirationDateTime, reason);
            blacklistRepository.save(blacklist);
            log.info("토큰을 블랙리스트에 추가: reason={}, expiration={}", reason, expirationDateTime);
        } catch (Exception e) {
            log.error("블랙리스트 추가 실패: error={}", e.getMessage(), e);
            throw new RuntimeException("블랙리스트 추가 실패", e);
        }
    }

    public boolean isBlacklisted(String token) {
        return blacklistRepository.existsByToken(token);
    }

    @Scheduled(cron = "0 0 2 * * ?") // 매일 새벽 2시 실행
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = blacklistRepository.deleteExpiredTokens(LocalDateTime.now());
        log.info("만료된 블랙리스트 토큰 정리 완료: deleted={}", deleted);
    }

    private String ensureBase64(String value) {
        try {
            Decoders.BASE64.decode(value);
            return value;
        } catch (Exception e) {
            return java.util.Base64.getEncoder().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}

