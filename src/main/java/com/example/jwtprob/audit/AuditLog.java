package com.example.jwtprob.audit;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(
    name = "audit_logs",
    indexes = {
        @Index(name = "idx_audit_username", columnList = "username"),
        @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_action", columnList = "action")
    }
)
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String username; // 누가

    @Column(nullable = false, length = 100)
    private String action; // 무엇을 (메서드명 또는 설명)

    @Column(length = 255)
    private String resource; // 어떤 리소스 (예: User#123, POST:WRITE)

    @Column(length = 100)
    private String httpMethod; // GET, POST, DELETE...

    @Column(length = 500)
    private String requestUri; // /api/v2/users/123

    @Column(length = 50)
    private String ipAddress; // 클라이언트 IP

    @Column(nullable = false)
    private LocalDateTime timestamp; // 언제

    @Column(nullable = false, length = 20)
    private String result; // SUCCESS, FAILURE, UNAUTHORIZED

    @Column
    private Long durationMs; // 실행 시간 (밀리초)

    @Column(length = 1000)
    private String errorMessage; // 실패 시 에러 메시지

    protected AuditLog() {
    }

    public AuditLog(String username, String action, String resource) {
        this.username = username;
        this.action = action;
        this.resource = resource;
        this.timestamp = LocalDateTime.now();
        this.result = "SUCCESS";
    }

    // Builder 패턴
    public static AuditLogBuilder builder() {
        return new AuditLogBuilder();
    }

    public static class AuditLogBuilder {
        private String username;
        private String action;
        private String resource;
        private String httpMethod;
        private String requestUri;
        private String ipAddress;
        private LocalDateTime timestamp;
        private String result;
        private Long durationMs;
        private String errorMessage;

        public AuditLogBuilder username(String username) {
            this.username = username;
            return this;
        }

        public AuditLogBuilder action(String action) {
            this.action = action;
            return this;
        }

        public AuditLogBuilder resource(String resource) {
            this.resource = resource;
            return this;
        }

        public AuditLogBuilder httpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
            return this;
        }

        public AuditLogBuilder requestUri(String requestUri) {
            this.requestUri = requestUri;
            return this;
        }

        public AuditLogBuilder ipAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public AuditLogBuilder timestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public AuditLogBuilder result(String result) {
            this.result = result;
            return this;
        }

        public AuditLogBuilder durationMs(Long durationMs) {
            this.durationMs = durationMs;
            return this;
        }

        public AuditLogBuilder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public AuditLog build() {
            AuditLog log = new AuditLog();
            log.username = this.username;
            log.action = this.action;
            log.resource = this.resource;
            log.httpMethod = this.httpMethod;
            log.requestUri = this.requestUri;
            log.ipAddress = this.ipAddress;
            log.timestamp = this.timestamp != null ? this.timestamp : LocalDateTime.now();
            log.result = this.result != null ? this.result : "SUCCESS";
            log.durationMs = this.durationMs;
            log.errorMessage = this.errorMessage;
            return log;
        }
    }

    // Getters
    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getAction() {
        return action;
    }

    public String getResource() {
        return resource;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getResult() {
        return result;
    }

    public Long getDurationMs() {
        return durationMs;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s - %s %s (%s) - %s (%dms)",
                timestamp, username, httpMethod, requestUri, action, result, durationMs);
    }
}

