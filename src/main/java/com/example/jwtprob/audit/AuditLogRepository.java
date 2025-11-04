package com.example.jwtprob.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    // 사용자별 조회
    Page<AuditLog> findByUsernameOrderByTimestampDesc(String username, Pageable pageable);

    // 결과별 조회 (성공/실패)
    Page<AuditLog> findByResultOrderByTimestampDesc(String result, Pageable pageable);

    // 기간별 조회
    @Query("SELECT a FROM AuditLog a WHERE a.timestamp BETWEEN :start AND :end ORDER BY a.timestamp DESC")
    List<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    // 특정 액션 조회
    Page<AuditLog> findByActionContainingIgnoreCaseOrderByTimestampDesc(String action, Pageable pageable);

    // 최근 N개 조회
    List<AuditLog> findTop100ByOrderByTimestampDesc();

    // 실패한 감사 로그만 조회
    @Query("SELECT a FROM AuditLog a WHERE a.result = 'FAILURE' OR a.result = 'UNAUTHORIZED' ORDER BY a.timestamp DESC")
    Page<AuditLog> findFailedAudits(Pageable pageable);
}

