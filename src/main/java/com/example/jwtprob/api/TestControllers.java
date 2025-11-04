package com.example.jwtprob.api;

import com.example.jwtprob.audit.Audited;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestControllers {

    // ============= 공개 API =============
    @GetMapping("/api/public")
    @Audited(action = "PUBLIC_VIEW", resource = "Public")
    public Map<String, Object> publicEndpoint() {
        return Map.of(
                "message", "공개 API - 누구나 접근 가능",
                "requiredRole", "없음"
        );
    }

    // ============= GUEST 레벨 (최하위) =============
    @PreAuthorize("hasRole('GUEST')")
    @GetMapping("/api/guest/view")
    @Audited(action = "GUEST_VIEW", resource = "Guest")
    public Map<String, Object> guestView(Authentication authentication) {
        return Map.of(
                "message", "게스트 읽기 전용",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "description", "GUEST 이상 접근 가능 (계층: GUEST < USER < DEV < MANAGER < ADMIN < SUPER_ADMIN)"
        );
    }

    // ============= USER 레벨 =============
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/api/user/info")
    public Map<String, Object> userInfo(Authentication authentication) {
        return Map.of(
                "message", "사용자 정보 조회",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "description", "USER 이상 접근 가능 (GUEST는 불가)"
        );
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/api/user/dashboard")
    public Map<String, Object> userDashboard(Authentication authentication) {
        return Map.of(
                "message", "사용자 대시보드",
                "user", authentication.getName(),
                "features", "기본 기능만 사용 가능"
        );
    }

    // ============= DEV 레벨 =============
    @PreAuthorize("hasRole('DEV')")
    @GetMapping("/api/dev/tools")
    public Map<String, Object> devTools(Authentication authentication) {
        return Map.of(
                "message", "개발자 도구",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "description", "DEV 이상 접근 가능 (USER, GUEST는 불가)"
        );
    }

    @PreAuthorize("hasRole('DEV')")
    @GetMapping("/api/dev/logs")
    public Map<String, Object> devLogs(Authentication authentication) {
        return Map.of(
                "message", "시스템 로그 조회",
                "user", authentication.getName(),
                "logLevel", "DEBUG"
        );
    }

    // ============= MANAGER 레벨 =============
    @PreAuthorize("hasRole('MANAGER')")
    @GetMapping("/api/manager/team")
    public Map<String, Object> managerTeam(Authentication authentication) {
        return Map.of(
                "message", "팀 관리",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "description", "MANAGER 이상 접근 가능 (DEV, USER, GUEST는 불가)"
        );
    }

    @PreAuthorize("hasRole('MANAGER')")
    @GetMapping("/api/manager/reports")
    public Map<String, Object> managerReports(Authentication authentication) {
        return Map.of(
                "message", "팀 보고서 조회",
                "user", authentication.getName(),
                "reports", "월간 실적, 팀원 평가"
        );
    }

    // ============= ADMIN 레벨 =============
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin/panel")
    public Map<String, Object> adminPanel(Authentication authentication) {
        return Map.of(
                "message", "관리자 패널",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "description", "ADMIN 이상 접근 가능 (MANAGER, DEV, USER, GUEST는 불가)"
        );
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin/users")
    public Map<String, Object> adminUsers(Authentication authentication) {
        return Map.of(
                "message", "사용자 관리",
                "user", authentication.getName(),
                "actions", "조회, 수정, 비활성화"
        );
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin/settings")
    public Map<String, Object> adminSettings(Authentication authentication) {
        return Map.of(
                "message", "시스템 설정",
                "user", authentication.getName(),
                "permissions", "시스템 설정 변경 가능"
        );
    }

    // ============= SUPER_ADMIN 레벨 (최상위) =============
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/api/superadmin/control")
    public Map<String, Object> superAdminControl(Authentication authentication) {
        return Map.of(
                "message", "최고 관리자 제어판",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "description", "SUPER_ADMIN만 접근 가능 (모든 권한 포함)"
        );
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/api/superadmin/database")
    public Map<String, Object> superAdminDatabase(Authentication authentication) {
        return Map.of(
                "message", "데이터베이스 직접 제어",
                "user", authentication.getName(),
                "warnings", "위험한 작업 포함"
        );
    }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/api/superadmin/security")
    public Map<String, Object> superAdminSecurity(Authentication authentication) {
        return Map.of(
                "message", "보안 설정 관리",
                "user", authentication.getName(),
                "actions", "권한 부여, 토큰 무효화, IP 차단"
        );
    }

    // ============= 계층 테스트용 =============
    @GetMapping("/api/hierarchy/check")
    public Map<String, Object> hierarchyCheck(Authentication authentication) {
        if (authentication == null) {
            return Map.of("message", "인증되지 않음");
        }
        return Map.of(
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "hierarchy", Map.of(
                        "SUPER_ADMIN", "최상위 - 모든 API 접근 가능",
                        "ADMIN", "관리자 - ADMIN + MANAGER + DEV + USER + GUEST API 접근",
                        "MANAGER", "매니저 - MANAGER + DEV + USER + GUEST API 접근",
                        "DEV", "개발자 - DEV + USER + GUEST API 접근",
                        "USER", "사용자 - USER + GUEST API 접근",
                        "GUEST", "게스트 - GUEST API만 접근"
                )
        );
    }
}


