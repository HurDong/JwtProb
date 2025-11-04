# Spring Boot JWT Authentication + Role Hierarchy

Spring Boot 3 기반 JWT 인증 및 6단계 역할 계층 시스템

## 🎯 핵심 기능

- **JWT 인증** (HS256, BCrypt 암호화)
- **6단계 역할 계층** (GUEST → USER → DEV → MANAGER → ADMIN → SUPER_ADMIN)
- **Spring Security RoleHierarchy** 기반 자동 권한 상속
- **메서드 레벨 보안** (`@PreAuthorize`)
- **Swagger UI** (API 문서 자동화)

## 🚀 실행 방법

```bash
# 프로젝트 실행
./gradlew bootRun

# 서버: http://localhost:8080
# Swagger: http://localhost:8080/swagger-ui.html
# H2 Console: http://localhost:8080/h2-console
```

## 🔐 테스트 계정

| Username     | Password     | Role        | 접근 가능 API             |
| ------------ | ------------ | ----------- | ------------------------- |
| `guest`      | `guest`      | GUEST       | GUEST만                   |
| `user`       | `user`       | USER        | GUEST, USER               |
| `dev`        | `dev`        | DEV         | GUEST, USER, DEV          |
| `manager`    | `manager`    | MANAGER     | GUEST, USER, DEV, MANAGER |
| `admin`      | `admin`      | ADMIN       | 위 + ADMIN                |
| `superadmin` | `superadmin` | SUPER_ADMIN | 전체                      |

## 📡 주요 API

### 인증

```bash
# 회원가입
POST /signup/guest        # GUEST 권한
POST /signup              # USER 권한
POST /signup/dev          # DEV 권한
POST /signup/manager      # MANAGER 권한
POST /signup/admin        # ADMIN 권한
POST /signup/superadmin   # SUPER_ADMIN 권한

# 로그인
POST /login
{
  "username": "admin",
  "password": "admin"
}
# Response: { "token": "eyJhbG..." }
```

### 테스트 API (역할별)

```bash
GET /api/guest/welcome              # GUEST+
GET /api/user/dashboard             # USER+
GET /api/dev/tools                  # DEV+
GET /api/manager/team               # MANAGER+
GET /api/admin/panel                # ADMIN+
GET /api/superadmin/system          # SUPER_ADMIN

# 인증 헤더
Authorization: Bearer <JWT_TOKEN>
```

## 🏗️ 역할 계층 구조

```
ROLE_SUPER_ADMIN (전체 권한)
    ↓
ROLE_ADMIN
    ↓
ROLE_MANAGER
    ↓
ROLE_DEV
    ↓
ROLE_USER
    ↓
ROLE_GUEST (최소 권한)
```

**상위 역할은 하위 역할의 모든 권한을 자동 상속합니다.**

예: `MANAGER`로 로그인 → DEV, USER, GUEST API 모두 접근 가능

## 🛠️ 기술 스택

- **Spring Boot 3.4.1**
- **Spring Security 6**
- **JWT** (JJWT 0.12.6)
- **Spring Data JPA**
- **H2 Database** (in-memory)
- **Gradle**
- **Springdoc OpenAPI 3** (Swagger)

## 📁 프로젝트 구조

```
src/main/java/com/example/jwtprob/
├── api/
│   ├── AuthController.java          # 회원가입/로그인
│   └── TestControllers.java         # 역할별 테스트 API (17개)
├── security/
│   ├── SecurityConfig.java          # 보안 설정 + RoleHierarchy
│   ├── JwtAuthenticationFilter.java # JWT 필터
│   ├── JwtTokenProvider.java        # JWT 생성/검증
│   └── JwtProperties.java           # JWT 설정
├── user/
│   ├── UserAccount.java             # User 엔티티
│   ├── UserRepository.java          # JPA Repository
│   └── Role.java                    # Role Enum (6단계)
└── bootstrap/
    └── DataInitializer.java         # 더미 계정 생성
```

## 🔍 핵심 코드

### RoleHierarchy 설정

```java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy("""
        ROLE_SUPER_ADMIN > ROLE_ADMIN
        ROLE_ADMIN > ROLE_MANAGER
        ROLE_MANAGER > ROLE_DEV
        ROLE_DEV > ROLE_USER
        ROLE_USER > ROLE_GUEST
        """);
    return hierarchy;
}
```

### 메서드 레벨 보안

```java
@GetMapping("/api/admin/panel")
@PreAuthorize("hasRole('ADMIN')")  // ADMIN 이상만 접근 가능
public ResponseEntity<?> adminPanel() {
    return ResponseEntity.ok("Admin Panel");
}
```

## 🧪 테스트 시나리오

```bash
# 1. 로그인 (dev 계정)
POST http://localhost:8080/login
{"username": "dev", "password": "dev"}

# 2. Token 복사
TOKEN="eyJhbGciOiJIUzI1NiJ9..."

# 3. API 테스트
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/dev/tools     # ✅ 성공 (본인 권한)

curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/user/dashboard  # ✅ 성공 (하위 권한)

curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/admin/panel   # ❌ 403 (상위 권한)
```

## 📝 학습 포인트

1. **JWT 인증 흐름**: 로그인 → JWT 발급 → 요청마다 검증
2. **RoleHierarchy**: 상속 구조로 권한 관리 간소화
3. **@PreAuthorize**: 메서드 레벨 세밀한 권한 제어
4. **Stateless 아키텍처**: 세션 없이 JWT로 인증 유지
5. **BCrypt**: 비밀번호 단방향 암호화

## 🔗 참고 링크

- [Spring Security RoleHierarchy](https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html)
- [JJWT Documentation](https://github.com/jwtk/jjwt)
- [Swagger UI](http://localhost:8080/swagger-ui.html)
