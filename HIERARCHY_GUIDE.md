# 🎯 계층적 권한 시스템 가이드

## 📊 권한 계층 구조

```
ROLE_SUPER_ADMIN (최고 관리자) ⭐⭐⭐⭐⭐⭐
    ↓ 모든 하위 권한 포함
ROLE_ADMIN (일반 관리자) ⭐⭐⭐⭐⭐
    ↓ MANAGER + DEV + USER + GUEST 권한 포함
ROLE_MANAGER (매니저) ⭐⭐⭐⭐
    ↓ DEV + USER + GUEST 권한 포함
ROLE_DEV (개발자) ⭐⭐⭐
    ↓ USER + GUEST 권한 포함
ROLE_USER (일반 사용자) ⭐⭐
    ↓ GUEST 권한 포함
ROLE_GUEST (게스트) ⭐
    ↓ 최하위 권한
```

**계층 규칙:**

- 상위 권한은 모든 하위 권한의 API에 접근 가능
- 예: `ROLE_ADMIN`은 `/api/user/info`, `/api/dev/tools`, `/api/manager/team` 모두 접근 가능
- 예: `ROLE_USER`는 `/api/guest/view`, `/api/user/info`만 접근 가능

---

## 👥 더미 계정

| Username     | Password     | Role             | 설명               |
| ------------ | ------------ | ---------------- | ------------------ |
| `guest`      | `guest`      | ROLE_GUEST       | 게스트 - 읽기 전용 |
| `user`       | `user`       | ROLE_USER        | 일반 사용자        |
| `dev`        | `dev`        | ROLE_DEV         | 개발자             |
| `manager`    | `manager`    | ROLE_MANAGER     | 매니저             |
| `admin`      | `admin`      | ROLE_ADMIN       | 관리자             |
| `superadmin` | `superadmin` | ROLE_SUPER_ADMIN | 최고 관리자        |

---

## 🔐 회원가입 API

| 엔드포인트                | 부여되는 권한    |
| ------------------------- | ---------------- |
| `POST /signup/guest`      | ROLE_GUEST       |
| `POST /signup`            | ROLE_USER        |
| `POST /signup/dev`        | ROLE_DEV         |
| `POST /signup/manager`    | ROLE_MANAGER     |
| `POST /signup/admin`      | ROLE_ADMIN       |
| `POST /signup/superadmin` | ROLE_SUPER_ADMIN |

**요청 예시:**

```json
POST /signup/manager
{
  "username": "mymanager",
  "password": "pass123"
}
```

---

## 🎯 API 접근 권한 매트릭스

### 공개 API

| API                        | 설명           | 필요 권한     |
| -------------------------- | -------------- | ------------- |
| `GET /api/public`          | 공개 API       | 없음 (누구나) |
| `GET /api/hierarchy/check` | 권한 계층 확인 | 인증 필요     |

### GUEST 레벨 (⭐)

| API                   | 설명        | 접근 가능 계정                               |
| --------------------- | ----------- | -------------------------------------------- |
| `GET /api/guest/view` | 게스트 읽기 | guest, user, dev, manager, admin, superadmin |

### USER 레벨 (⭐⭐)

| API                       | 설명            | 접근 가능 계정                        |
| ------------------------- | --------------- | ------------------------------------- |
| `GET /api/user/info`      | 사용자 정보     | user, dev, manager, admin, superadmin |
| `GET /api/user/dashboard` | 사용자 대시보드 | user, dev, manager, admin, superadmin |

### DEV 레벨 (⭐⭐⭐)

| API                  | 설명        | 접근 가능 계정                  |
| -------------------- | ----------- | ------------------------------- |
| `GET /api/dev/tools` | 개발자 도구 | dev, manager, admin, superadmin |
| `GET /api/dev/logs`  | 시스템 로그 | dev, manager, admin, superadmin |

### MANAGER 레벨 (⭐⭐⭐⭐)

| API                        | 설명      | 접근 가능 계정             |
| -------------------------- | --------- | -------------------------- |
| `GET /api/manager/team`    | 팀 관리   | manager, admin, superadmin |
| `GET /api/manager/reports` | 팀 보고서 | manager, admin, superadmin |

### ADMIN 레벨 (⭐⭐⭐⭐⭐)

| API                       | 설명        | 접근 가능 계정    |
| ------------------------- | ----------- | ----------------- |
| `GET /api/admin/panel`    | 관리자 패널 | admin, superadmin |
| `GET /api/admin/users`    | 사용자 관리 | admin, superadmin |
| `GET /api/admin/settings` | 시스템 설정 | admin, superadmin |

### SUPER_ADMIN 레벨 (⭐⭐⭐⭐⭐⭐)

| API                            | 설명               | 접근 가능 계정 |
| ------------------------------ | ------------------ | -------------- |
| `GET /api/superadmin/control`  | 최고 관리자 제어판 | superadmin만   |
| `GET /api/superadmin/database` | DB 직접 제어       | superadmin만   |
| `GET /api/superadmin/security` | 보안 설정          | superadmin만   |

---

## 🧪 테스트 시나리오

### 시나리오 1: GUEST 계정 테스트

```bash
# 1. 로그인
POST /login
{"username": "guest", "password": "guest"}
# 응답: {"token": "..."}

# 2. 접근 테스트
GET /api/guest/view (with token) → ✅ 200 OK
GET /api/user/info (with token) → ❌ 403 Forbidden
GET /api/dev/tools (with token) → ❌ 403 Forbidden
```

### 시나리오 2: USER 계정 테스트

```bash
POST /login
{"username": "user", "password": "user"}

GET /api/guest/view → ✅ 200 OK (계층 덕분에 GUEST API 접근 가능)
GET /api/user/info → ✅ 200 OK
GET /api/user/dashboard → ✅ 200 OK
GET /api/dev/tools → ❌ 403 Forbidden
GET /api/manager/team → ❌ 403 Forbidden
```

### 시나리오 3: DEV 계정 테스트

```bash
POST /login
{"username": "dev", "password": "dev"}

GET /api/guest/view → ✅ 200 OK (GUEST 권한 포함)
GET /api/user/info → ✅ 200 OK (USER 권한 포함)
GET /api/dev/tools → ✅ 200 OK (자신의 권한)
GET /api/dev/logs → ✅ 200 OK
GET /api/manager/team → ❌ 403 Forbidden (상위 권한)
```

### 시나리오 4: MANAGER 계정 테스트

```bash
POST /login
{"username": "manager", "password": "manager"}

GET /api/guest/view → ✅ 200 OK
GET /api/user/info → ✅ 200 OK
GET /api/dev/tools → ✅ 200 OK (DEV 권한 포함)
GET /api/manager/team → ✅ 200 OK
GET /api/manager/reports → ✅ 200 OK
GET /api/admin/panel → ❌ 403 Forbidden
```

### 시나리오 5: ADMIN 계정 테스트

```bash
POST /login
{"username": "admin", "password": "admin"}

GET /api/guest/view → ✅ 200 OK
GET /api/user/info → ✅ 200 OK
GET /api/dev/tools → ✅ 200 OK
GET /api/manager/team → ✅ 200 OK (MANAGER 권한 포함)
GET /api/admin/panel → ✅ 200 OK
GET /api/admin/users → ✅ 200 OK
GET /api/superadmin/control → ❌ 403 Forbidden
```

### 시나리오 6: SUPER_ADMIN 계정 테스트 ⭐

```bash
POST /login
{"username": "superadmin", "password": "superadmin"}

# 모든 API 접근 가능!
GET /api/guest/view → ✅ 200 OK
GET /api/user/info → ✅ 200 OK
GET /api/dev/tools → ✅ 200 OK
GET /api/manager/team → ✅ 200 OK
GET /api/admin/panel → ✅ 200 OK
GET /api/superadmin/control → ✅ 200 OK
GET /api/superadmin/database → ✅ 200 OK
GET /api/superadmin/security → ✅ 200 OK
```

---

## 🚀 Swagger에서 테스트

1. **서버 실행**

   ```bash
   ./gradlew bootRun
   ```

2. **Swagger 접속**

   ```
   http://localhost:8080/swagger-ui.html
   ```

3. **로그인 후 토큰 받기**

   - `POST /login` 실행
   - 원하는 계정으로 로그인 (예: `admin`/`admin`)
   - 응답에서 `token` 복사

4. **Authorize 설정**

   - 우측 상단 🔓 **Authorize** 버튼 클릭
   - 토큰 입력 (Bearer는 자동 추가됨)
   - **Authorize** → **Close**

5. **API 테스트**
   - 각 엔드포인트 실행
   - 권한에 따라 200 OK 또는 403 Forbidden 확인

---

## 📋 권한 계층의 장점

### 1. 코드 간결화

**이전 방식:**

```java
.requestMatchers("/api/user/**").hasAnyRole("USER", "DEV", "MANAGER", "ADMIN", "SUPER_ADMIN")
```

**계층 방식:**

```java
@PreAuthorize("hasRole('USER')")  // 자동으로 상위 권한도 포함
```

### 2. 유지보수 용이

- 새 권한 추가 시 계층만 조정하면 자동 반영
- 각 API마다 모든 권한 나열 불필요

### 3. 직관적인 권한 관리

- 권한 상속 구조가 명확
- 실제 조직 구조와 일치

### 4. 확장 가능

- 중간 계층 추가 쉬움 (예: SENIOR_DEV, TEAM_LEAD 등)

---

## 🔧 커스터마이징

### 계층 구조 변경

`SecurityConfig.java`의 `roleHierarchy()` 메서드 수정:

```java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    String hierarchyString = """
            ROLE_SUPER_ADMIN > ROLE_ADMIN
            ROLE_ADMIN > ROLE_SENIOR_DEV
            ROLE_SENIOR_DEV > ROLE_DEV
            ROLE_DEV > ROLE_USER
            ROLE_USER > ROLE_GUEST
            """;
    hierarchy.setHierarchy(hierarchyString);
    return hierarchy;
}
```

### 새 Role 추가

1. `Role.java`에 enum 추가
2. 계층 설정에 추가
3. 회원가입 API 추가
4. 테스트 컨트롤러에 API 추가
5. 더미 계정 추가

---

## 🎉 완성!

이제 6단계 계층적 권한 시스템이 완성되었습니다!

- ✅ 6개 권한 레벨 (GUEST ~ SUPER_ADMIN)
- ✅ 자동 권한 상속 (Role Hierarchy)
- ✅ 17개 테스트 API (레벨별 2~3개씩)
- ✅ 6개 더미 계정
- ✅ 메서드 레벨 보안 (`@PreAuthorize`)
- ✅ Swagger 통합 테스트

**즐거운 개발 되세요!** 🚀
