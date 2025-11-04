package com.example.jwtprob.audit;

import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;

/**
 * AOP 기반 자동 감사 로깅
 * 
 * @Audited 어노테이션이 붙은 메서드 실행 시:
 * 1. 실행 전 시간 기록
 * 2. 메서드 실행
 * 3. 실행 후 시간 기록
 * 4. 성공/실패 여부, 실행 시간 등을 DB에 저장
 */
@Aspect
@Component
public class AuditAspect {

    private static final Logger log = LoggerFactory.getLogger(AuditAspect.class);

    private final AuditLogRepository auditLogRepository;

    public AuditAspect(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * @Audited 어노테이션이 붙은 모든 메서드를 감싸서 실행
     */
    @Around("@annotation(audited)")
    public Object logAudit(ProceedingJoinPoint joinPoint, Audited audited) throws Throwable {
        long startTime = System.currentTimeMillis();
        
        // 현재 사용자 정보
        String username = getCurrentUsername();
        
        // HTTP 요청 정보
        HttpServletRequest request = getCurrentRequest();
        String httpMethod = request != null ? request.getMethod() : "UNKNOWN";
        String requestUri = request != null ? request.getRequestURI() : "UNKNOWN";
        String ipAddress = request != null ? getClientIp(request) : "UNKNOWN";
        
        // 어노테이션 정보
        String action = audited.action().isEmpty() ? getMethodName(joinPoint) : audited.action();
        String resource = audited.resource();
        
        log.info("🔍 [AUDIT] 시작: {} | {} | {} {}", username, action, httpMethod, requestUri);
        
        AuditLog auditLog = null;
        
        try {
            // 실제 메서드 실행
            Object result = joinPoint.proceed();
            
            // 성공 시 감사 로그 생성
            long duration = System.currentTimeMillis() - startTime;
            
            auditLog = AuditLog.builder()
                .username(username)
                .action(action)
                .resource(resource)
                .httpMethod(httpMethod)
                .requestUri(requestUri)
                .ipAddress(ipAddress)
                .timestamp(LocalDateTime.now())
                .result("SUCCESS")
                .durationMs(duration)
                .build();
            
            auditLogRepository.save(auditLog);
            
            log.info("✅ [AUDIT] 성공: {} | {} | {}ms", username, action, duration);
            
            return result;
            
        } catch (Exception e) {
            // 실패 시 감사 로그 생성
            long duration = System.currentTimeMillis() - startTime;
            
            String result = isUnauthorized(e) ? "UNAUTHORIZED" : "FAILURE";
            
            auditLog = AuditLog.builder()
                .username(username)
                .action(action)
                .resource(resource)
                .httpMethod(httpMethod)
                .requestUri(requestUri)
                .ipAddress(ipAddress)
                .timestamp(LocalDateTime.now())
                .result(result)
                .durationMs(duration)
                .errorMessage(e.getMessage())
                .build();
            
            auditLogRepository.save(auditLog);
            
            log.error("❌ [AUDIT] 실패: {} | {} | {} | {}ms", username, action, e.getMessage(), duration);
            
            throw e;
        }
    }

    /**
     * 현재 인증된 사용자명 가져오기
     */
    private String getCurrentUsername() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
                return auth.getName();
            }
        } catch (Exception e) {
            log.debug("인증 정보 없음: {}", e.getMessage());
        }
        return "ANONYMOUS";
    }

    /**
     * 현재 HTTP 요청 가져오기
     */
    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attributes != null ? attributes.getRequest() : null;
        } catch (Exception e) {
            log.debug("HTTP 요청 정보 없음: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 클라이언트 IP 주소 가져오기
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    /**
     * 메서드명 가져오기
     */
    private String getMethodName(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        return signature.getMethod().getName();
    }

    /**
     * 인증 관련 예외인지 확인
     */
    private boolean isUnauthorized(Exception e) {
        return e instanceof org.springframework.security.access.AccessDeniedException ||
               e instanceof org.springframework.security.core.AuthenticationException;
    }
}

