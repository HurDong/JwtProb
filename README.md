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
# Response: 
# {
#   "accessToken": "eyJhbG...",
#   "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
#   "tokenType": "Bearer",
#   "expiresIn": 900
# }

# Access Token 재발급
POST /refresh
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
# Response: { "accessToken": "eyJhbG...", "expiresIn": 900 }

# 일반 로그아웃 (클라이언트 방식)
POST /logout
Authorization: Bearer <TOKEN>
# 서버는 성공 응답만, 클라이언트가 토큰 삭제

# 블랙리스트 로그아웃 (서버 방식)
POST /logout/blacklist
Authorization: Bearer <TOKEN>
# 서버가 토큰 무효화 (진짜 로그아웃)
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

## 🔄 Refresh Token 패턴

| 토큰              | 만료 시간 | 저장 위치 | 용도                          |
| ----------------- | --------- | --------- | ----------------------------- |
| **Access Token**  | 15분      | 클라이언트 | API 요청 인증                 |
| **Refresh Token** | 7일       | DB        | Access Token 재발급           |

**흐름:**
1. 로그인 → Access Token (15분) + Refresh Token (7일) 발급
2. API 요청 → Access Token 사용
3. Access Token 만료 → `/refresh`로 재발급 (Refresh Token 제출)
4. 로그아웃 → Refresh Token DB에서 삭제 → 재발급 불가

**장점:**
- Access Token 탈취되어도 15분만 유효
- Refresh Token은 DB 저장 → 강제 무효화 가능
- 로그아웃 시 Refresh Token 삭제 → 완전한 로그아웃

## 🔓 로그아웃 방식 비교

| 특징              | 일반 로그아웃 (`/logout`)       | 블랙리스트 로그아웃 (`/logout/blacklist`)      |
| ----------------- | ------------------------------- | ---------------------------------------------- |
| **서버 처리**     | Refresh Token 삭제              | Access Token 블랙리스트 + Refresh Token 삭제   |
| **Access Token**  | 만료 전까지 유효 (15분)         | 즉시 무효화                                    |
| **Refresh Token** | 삭제됨 (재발급 불가)            | 삭제됨 (재발급 불가)                           |
| **보안성**        | 중간 (최대 15분 위험)           | 높음 (즉시 차단)                               |
| **성능**          | 빠름                            | 약간 느림 (블랙리스트 확인)                    |
| **사용 케이스**   | 일반 웹사이트                   | 금융/관리자 시스템                             |

**권장:** 일반 서비스는 `/logout` (Refresh Token 패턴으로 충분), 보안 중요 시 `/logout/blacklist` 사용

## 📝 학습 포인트

1. **JWT 인증 흐름**: 로그인 → JWT 발급 → 요청마다 검증
2. **Refresh Token 패턴**: Access Token (15분) + Refresh Token (7일)으로 보안 강화
3. **RoleHierarchy**: 상속 구조로 권한 관리 간소화
4. **@PreAuthorize**: 메서드 레벨 세밀한 권한 제어
5. **Stateless 아키텍처**: 세션 없이 JWT로 인증 유지 (부분적 Stateful: Refresh Token)
6. **BCrypt**: 비밀번호 단방향 암호화
7. **Token Blacklist**: 서버 측 토큰 무효화로 강제 로그아웃 구현

## 🔗 참고 링크

- [Spring Security RoleHierarchy](https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html)
- [JJWT Documentation](https://github.com/jwtk/jjwt)
- [Swagger UI](http://localhost:8080/swagger-ui.html)
