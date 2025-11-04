package com.example.jwtprob.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final long REFRESH_TOKEN_VALIDITY_DAYS = 7;

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional
    public String createRefreshToken(String username, String deviceInfo) {
        // 기존 Refresh Token 삭제 (한 계정당 하나만)
        refreshTokenRepository.deleteByUsername(username);

        // 새 Refresh Token 생성
        String token = UUID.randomUUID().toString();
        LocalDateTime expiryDate = LocalDateTime.now().plusDays(REFRESH_TOKEN_VALIDITY_DAYS);

        RefreshToken refreshToken = new RefreshToken(token, username, expiryDate, deviceInfo);
        refreshTokenRepository.save(refreshToken);

        log.info("Refresh Token 생성: username={}, expiryDate={}", username, expiryDate);
        return token;
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional(readOnly = true)
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh Token이 만료되었습니다. 다시 로그인하세요.");
        }
        return token;
    }

    @Transactional
    public void deleteByUsername(String username) {
        refreshTokenRepository.deleteByUsername(username);
        log.info("Refresh Token 삭제: username={}", username);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
        log.info("Refresh Token 삭제: token={}", token.substring(0, 8) + "...");
    }

    @Scheduled(cron = "0 0 3 * * ?") // 매일 새벽 3시
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        log.info("만료된 Refresh Token 정리 완료: deleted={}", deleted);
    }
}

