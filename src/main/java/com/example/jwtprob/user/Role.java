package com.example.jwtprob.user;

public enum Role {
    ROLE_GUEST,        // 최하위: 제한된 읽기 권한만
    ROLE_USER,         // 일반 사용자: 기본 기능
    ROLE_DEV,          // 개발자: 개발 도구 접근
    ROLE_MANAGER,      // 매니저: 팀 관리 기능
    ROLE_ADMIN,        // 관리자: 시스템 관리
    ROLE_SUPER_ADMIN   // 최고 관리자: 모든 권한
}


