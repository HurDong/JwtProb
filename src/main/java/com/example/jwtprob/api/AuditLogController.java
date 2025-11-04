package com.example.jwtprob.api;

import com.example.jwtprob.api.dto.ApiResponse;
import com.example.jwtprob.audit.AuditLog;
import com.example.jwtprob.audit.AuditLogRepository;
import com.example.jwtprob.audit.Audited;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/audit-logs")
@PreAuthorize("hasRole('ROLE_SUPER_ADMIN') or hasRole('ROLE_ADMIN')")
public class AuditLogController {

    private final AuditLogRepository auditLogRepository;

    public AuditLogController(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * 모든 감사 로그 조회 (페이징)
     */
    @GetMapping
    @Audited(action = "AUDIT_LOG_VIEW_ALL", resource = "AuditLog")
    public ResponseEntity<?> getAllAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        Page<AuditLog> logs = auditLogRepository.findAll(pageable);
        
        return ResponseEntity.ok(ApiResponse.success(
            "감사 로그 조회 성공",
            Map.of(
                "content", logs.getContent(),
                "totalElements", logs.getTotalElements(),
                "totalPages", logs.getTotalPages(),
                "currentPage", logs.getNumber()
            )
        ));
    }

    /**
     * 최근 100개 감사 로그 조회
     */
    @GetMapping("/recent")
    @Audited(action = "AUDIT_LOG_VIEW_RECENT", resource = "AuditLog")
    public ResponseEntity<?> getRecentAuditLogs() {
        List<AuditLog> logs = auditLogRepository.findTop100ByOrderByTimestampDesc();
        
        return ResponseEntity.ok(ApiResponse.success(
            "최근 감사 로그 조회 성공",
            Map.of("logs", logs, "count", logs.size())
        ));
    }

    /**
     * 특정 사용자의 감사 로그 조회
     */
    @GetMapping("/user/{username}")
    @Audited(action = "AUDIT_LOG_VIEW_BY_USER", resource = "AuditLog")
    public ResponseEntity<?> getAuditLogsByUser(
            @PathVariable String username,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<AuditLog> logs = auditLogRepository.findByUsernameOrderByTimestampDesc(username, pageable);
        
        return ResponseEntity.ok(ApiResponse.success(
            username + "의 감사 로그 조회 성공",
            Map.of(
                "username", username,
                "content", logs.getContent(),
                "totalElements", logs.getTotalElements(),
                "totalPages", logs.getTotalPages()
            )
        ));
    }

    /**
     * 실패한 감사 로그만 조회
     */
    @GetMapping("/failures")
    @Audited(action = "AUDIT_LOG_VIEW_FAILURES", resource = "AuditLog")
    public ResponseEntity<?> getFailedAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<AuditLog> logs = auditLogRepository.findFailedAudits(pageable);
        
        return ResponseEntity.ok(ApiResponse.success(
            "실패한 감사 로그 조회 성공",
            Map.of(
                "content", logs.getContent(),
                "totalElements", logs.getTotalElements()
            )
        ));
    }

    /**
     * 특정 액션 검색
     */
    @GetMapping("/search")
    @Audited(action = "AUDIT_LOG_SEARCH", resource = "AuditLog")
    public ResponseEntity<?> searchAuditLogs(
            @RequestParam String action,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<AuditLog> logs = auditLogRepository.findByActionContainingIgnoreCaseOrderByTimestampDesc(action, pageable);
        
        return ResponseEntity.ok(ApiResponse.success(
            "감사 로그 검색 성공",
            Map.of(
                "searchTerm", action,
                "content", logs.getContent(),
                "totalElements", logs.getTotalElements()
            )
        ));
    }

    /**
     * 기간별 조회
     */
    @GetMapping("/range")
    @Audited(action = "AUDIT_LOG_VIEW_BY_DATE_RANGE", resource = "AuditLog")
    public ResponseEntity<?> getAuditLogsByDateRange(
            @RequestParam String startDate,
            @RequestParam String endDate) {
        
        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        LocalDateTime start = LocalDateTime.parse(startDate, formatter);
        LocalDateTime end = LocalDateTime.parse(endDate, formatter);
        
        List<AuditLog> logs = auditLogRepository.findByTimestampBetween(start, end);
        
        return ResponseEntity.ok(ApiResponse.success(
            "기간별 감사 로그 조회 성공",
            Map.of(
                "startDate", startDate,
                "endDate", endDate,
                "logs", logs,
                "count", logs.size()
            )
        ));
    }

    /**
     * 감사 로그 통계
     */
    @GetMapping("/stats")
    @Audited(action = "AUDIT_LOG_VIEW_STATS", resource = "AuditLog")
    public ResponseEntity<?> getAuditLogStats() {
        long total = auditLogRepository.count();
        
        Pageable pageable = PageRequest.of(0, 1);
        long failures = auditLogRepository.findFailedAudits(pageable).getTotalElements();
        long successes = total - failures;
        
        return ResponseEntity.ok(ApiResponse.success(
            "감사 로그 통계 조회 성공",
            Map.of(
                "totalLogs", total,
                "successCount", successes,
                "failureCount", failures,
                "successRate", total > 0 ? (double) successes / total * 100 : 0
            )
        ));
    }
}

