# 🔐 JWT & Spring Security 완벽 가이드

> 이 문서는 실제 작성한 코드를 기반으로 JWT 인증과 Spring Security의 동작 원리를 설명합니다.

---

## 📑 목차

1. [전체 아키텍처](#전체-아키텍처)
2. [JWT란 무엇인가?](#jwt란-무엇인가)
3. [인증 흐름 (Authentication Flow)](#인증-흐름)
4. [핵심 컴포넌트 상세 설명](#핵심-컴포넌트-상세-설명)
5. [코드 실행 순서](#코드-실행-순서)
6. [보안 개념 이해](#보안-개념-이해)

---

## 전체 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                         클라이언트                               │
│                    (Swagger / Postman / 브라우저)               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ HTTP Request
                             │ Authorization: Bearer <JWT>
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                     Spring Security Filter Chain                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. JwtAuthenticationFilter (우리가 만든 필터)            │  │
│  │     - JWT 토큰 추출 및 검증                               │  │
│  │     - SecurityContext에 인증 정보 저장                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  2. UsernamePasswordAuthenticationFilter                  │  │
│  │     - 로그인 처리 (우리는 직접 처리해서 사용 안 함)       │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  3. Authorization Filter                                  │  │
│  │     - @PreAuthorize 검사                                  │  │
│  │     - Role Hierarchy 적용                                 │  │
│  └───────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                       Controller Layer                           │
│  ┌───────────────────┐  ┌────────────────────┐                  │
│  │  AuthController   │  │  TestControllers   │                  │
│  │  - 회원가입       │  │  - @PreAuthorize  │                  │
│  │  - 로그인         │  │  - 권한별 API     │                  │
│  └───────────────────┘  └────────────────────┘                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                       Service / Repository                       │
│  ┌───────────────────┐  ┌────────────────────┐                  │
│  │  UserRepository   │  │  JwtTokenProvider  │                  │
│  │  - DB 접근        │  │  - 토큰 생성/검증 │                  │
│  └───────────────────┘  └────────────────────┘                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                       Database (H2)                              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  users 테이블                                            │   │
│  │  - id, username, password (BCrypt), roles                │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## JWT란 무엇인가?

### JWT (JSON Web Token) 구조

JWT는 3개 부분으로 구성되며, 점(`.`)으로 구분됩니다:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjoiUk9MRV9BRE1JTiJ9.signature
    ↑ Header          ↑ Payload                                    ↑ Signature
```

#### 1. Header (헤더)
```json
{
  "alg": "HS256",      // 서명 알고리즘
  "typ": "JWT"         // 토큰 타입
}
```

#### 2. Payload (페이로드) - 실제 데이터
```json
{
  "sub": "admin",                    // subject: 사용자명
  "roles": "ROLE_ADMIN,ROLE_MANAGER", // 권한 정보
  "iat": 1699000000,                 // issued at: 발급 시간
  "exp": 1699003600                  // expiration: 만료 시간
}
```

#### 3. Signature (서명)
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

### JWT의 장점

✅ **Stateless (무상태)**
- 서버가 세션을 저장하지 않음
- 수평 확장(Scale-out)이 쉬움

✅ **Self-contained (자체 포함)**
- 토큰 자체에 사용자 정보가 들어있음
- DB 조회 없이 인증 가능

✅ **Cross-origin 지원**
- REST API, 마이크로서비스에 적합

### JWT의 단점

❌ **토큰 크기**
- Cookie보다 크기가 큼

❌ **토큰 무효화 어려움**
- 만료 전까지는 유효함 (블랙리스트 필요)

❌ **페이로드 암호화 안 됨**
- Base64 인코딩만 되어있어 누구나 디코딩 가능
- 민감한 정보는 담으면 안 됨

---

## 인증 흐름

### 📝 1. 회원가입 (Signup)

```
Client                   AuthController              UserRepository            Database
  │                            │                            │                      │
  │─POST /signup──────────────>│                            │                      │
  │ {"username":"dev",         │                            │                      │
  │  "password":"dev"}         │                            │                      │
  │                            │                            │                      │
  │                            │─1. existsByUsername()─────>│                      │
  │                            │<──false────────────────────│                      │
  │                            │                            │                      │
  │                            │─2. BCrypt.encode("dev")───>│                      │
  │                            │<──$2a$10$abc...───────────│                      │
  │                            │                            │                      │
  │                            │─3. new UserAccount()       │                      │
  │                            │   (username, encrypted_pw, │                      │
  │                            │    Set.of(ROLE_DEV))       │                      │
  │                            │                            │                      │
  │                            │─4. save()─────────────────>│──INSERT INTO users─>│
  │<──200 OK───────────────────│                            │                      │
  │ {"message":"회원가입 완료"}│                            │                      │
```

**코드 위치:** `AuthController.java - signup()`

```java
@PostMapping("/signup/dev")
public ResponseEntity<?> signupDev(@Valid @RequestBody SignupRequest request) {
    return createUser(request, Set.of(Role.ROLE_DEV));
}

private ResponseEntity<?> createUser(SignupRequest request, Set<Role> roles) {
    // 1. 중복 체크
    if (userRepository.existsByUsername(request.getUsername())) {
        return ResponseEntity.badRequest()
            .body(new ApiResponse("이미 존재하는 사용자명입니다."));
    }
    
    // 2. 비밀번호 암호화 (BCrypt)
    String encodedPassword = passwordEncoder.encode(request.getPassword());
    
    // 3. 사용자 생성 및 저장
    UserAccount user = new UserAccount(
        request.getUsername(),
        encodedPassword,
        roles
    );
    userRepository.save(user);
    
    return ResponseEntity.ok(new ApiResponse("회원가입 완료"));
}
```

---

### 🔑 2. 로그인 (Login) - JWT 발급

```
Client                   AuthController         AuthenticationManager    JwtTokenProvider
  │                            │                          │                      │
  │─POST /login───────────────>│                          │                      │
  │ {"username":"dev",         │                          │                      │
  │  "password":"dev"}         │                          │                      │
  │                            │                          │                      │
  │                            │─1. authenticate()───────>│                      │
  │                            │   (username, password)   │                      │
  │                            │                          │                      │
  │                            │                    [DB에서 사용자 조회]         │
  │                            │                    [BCrypt로 비밀번호 검증]     │
  │                            │                          │                      │
  │                            │<─2. Authentication───────│                      │
  │                            │   (UserAccount)          │                      │
  │                            │                          │                      │
  │                            │─3. generateToken()───────────────────────────>│
  │                            │   (username, roles)                            │
  │                            │                                                │
  │                            │<─4. JWT Token──────────────────────────────────│
  │                            │   "eyJhbGci..."                                │
  │<──200 OK───────────────────│                                                │
  │ {"token":"eyJhbGci..."}    │                                                │
```

**코드 위치:** `AuthController.java - login()`

```java
@PostMapping("/login")
public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
    log.info("=== 로그인 시도: username={}", request.getUsername());
    
    try {
        // 1. 인증 시도 (username + password)
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(), 
                request.getPassword()
            )
        );
        
        // 2. 인증 성공 - UserAccount 정보 추출
        UserAccount principal = (UserAccount) authentication.getPrincipal();
        log.info("=== 사용자 권한: username={}, roles={}", 
                 principal.getUsername(), principal.getRoles());
        
        // 3. JWT 토큰 생성
        String token = jwtTokenProvider.generateToken(
            principal.getUsername(), 
            principal.getRoles()
        );
        
        // 4. 토큰 반환
        return ResponseEntity.ok(new AuthResponse(token));
        
    } catch (Exception e) {
        log.error("=== 로그인 실패: username={}, error={}", 
                  request.getUsername(), e.getMessage());
        throw e;
    }
}
```

---

### 🔐 3. 인증된 API 호출

```
Client              JwtAuthenticationFilter    JwtTokenProvider    SecurityContext    Controller
  │                          │                        │                  │                │
  │─GET /api/admin/panel────>│                        │                  │                │
  │ Authorization: Bearer    │                        │                  │                │
  │ eyJhbGci...              │                        │                  │                │
  │                          │                        │                  │                │
  │                    1. 토큰 추출                   │                  │                │
  │                          │  "eyJhbGci..."         │                  │                │
  │                          │                        │                  │                │
  │                    2. 토큰 검증                   │                  │                │
  │                          │─validateToken()───────>│                  │                │
  │                          │<──true─────────────────│                  │                │
  │                          │                        │                  │                │
  │                    3. 사용자 정보 추출             │                  │                │
  │                          │─getUsername()─────────>│                  │                │
  │                          │<──"admin"──────────────│                  │                │
  │                          │─getRoles()────────────>│                  │                │
  │                          │<──[ROLE_ADMIN]─────────│                  │                │
  │                          │                        │                  │                │
  │                    4. SecurityContext에 저장       │                  │                │
  │                          │─setAuthentication()────────────────────>│                │
  │                          │                        │                  │                │
  │                    5. 권한 체크 (@PreAuthorize)    │                  │                │
  │                          │                        │    hasRole('ADMIN')?              │
  │                          │                        │                  │                │
  │                    6. Controller 실행             │                  │                │
  │                          │───────────────────────────────────────────────────────────>│
  │<─200 OK──────────────────────────────────────────────────────────────────────────────│
  │ {"message":"admin panel  │                        │                  │                │
  │  ok","user":"admin"}     │                        │                  │                │
```

**코드 위치:** `JwtAuthenticationFilter.java`

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtTokenProvider jwtTokenProvider;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) 
            throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        log.debug("=== JWT 필터 실행: method={}, uri={}", 
                  request.getMethod(), requestURI);
        
        // 1. Authorization 헤더에서 JWT 토큰 추출
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // "Bearer " 제거
            log.info("=== JWT 토큰 발견: uri={}, token length={}", 
                     requestURI, token.length());
            
            // 2. 토큰 검증
            if (jwtTokenProvider.validateToken(token)) {
                // 3. 토큰에서 사용자 정보 추출
                String username = jwtTokenProvider.getUsername(token);
                Set<Role> roles = jwtTokenProvider.getRoles(token);
                log.info("=== JWT 토큰 검증 성공: username={}, roles={}", 
                         username, roles);
                
                // 4. Spring Security 권한 객체로 변환
                var authorities = roles.stream()
                    .map(r -> new SimpleGrantedAuthority(r.name()))
                    .collect(Collectors.toSet());
                
                // 5. Authentication 객체 생성 및 SecurityContext에 저장
                var authentication = new UsernamePasswordAuthenticationToken(
                    username, null, authorities
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                log.info("=== SecurityContext에 인증 정보 저장 완료: username={}", username);
            } else {
                log.warn("=== JWT 토큰 검증 실패: uri={}", requestURI);
            }
        } else {
            log.debug("=== JWT 토큰 없음: uri={}", requestURI);
        }
        
        // 6. 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
```

---

## 핵심 컴포넌트 상세 설명

### 1️⃣ JwtTokenProvider - JWT 토큰 생성 및 검증

**역할:** JWT 토큰의 생성, 검증, 정보 추출

**코드 위치:** `security/JwtTokenProvider.java`

#### 📌 토큰 생성 (generateToken)

```java
public String generateToken(String username, Set<Role> roles) {
    long now = System.currentTimeMillis();
    Date issuedAt = new Date(now);
    Date expiry = new Date(now + properties.getExpirationMs()); // 1시간 후
    
    // roles를 CSV 형태로 변환
    String rolesCsv = roles.stream()
        .map(Enum::name)
        .sorted()
        .collect(Collectors.joining(","));
    
    return Jwts.builder()
        .setSubject(username)                    // "sub": "admin"
        .addClaims(Map.of("roles", rolesCsv))   // "roles": "ROLE_ADMIN"
        .setIssuedAt(issuedAt)                  // "iat": 1699000000
        .setExpiration(expiry)                  // "exp": 1699003600
        .signWith(key, SignatureAlgorithm.HS256) // HMAC SHA-256 서명
        .compact();
}
```

**생성된 토큰 구조:**
```json
{
  "sub": "admin",
  "roles": "ROLE_ADMIN,ROLE_MANAGER",
  "iat": 1699000000,
  "exp": 1699003600
}
```

#### 📌 토큰 검증 (validateToken)

```java
public boolean validateToken(String token) {
    try {
        parseClaims(token);  // 파싱 성공 = 검증 성공
        return true;
    } catch (Exception e) {
        // 만료, 서명 불일치, 형식 오류 등
        return false;
    }
}

private Jws<Claims> parseClaims(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(key)     // 서명 검증용 키
        .build()
        .parseClaimsJws(token); // 파싱 + 검증
}
```

**검증 항목:**
1. ✅ 서명 검증 (secret key로 검증)
2. ✅ 만료 시간 체크
3. ✅ 토큰 형식 검증

#### 📌 정보 추출

```java
public String getUsername(String token) {
    return parseClaims(token).getBody().getSubject();
}

public Set<Role> getRoles(String token) {
    Claims claims = parseClaims(token).getBody();
    String rolesStr = String.valueOf(claims.get("roles"));
    
    // "ROLE_ADMIN,ROLE_MANAGER" → Set<Role>
    return Arrays.stream(rolesStr.split(","))
        .map(String::trim)
        .map(Role::valueOf)
        .collect(Collectors.toSet());
}
```

---

### 2️⃣ SecurityConfig - Spring Security 설정

**역할:** 보안 정책, 필터 체인, 권한 계층 설정

**코드 위치:** `security/SecurityConfig.java`

#### 📌 핵심 설정

```java
@Configuration
@EnableMethodSecurity  // @PreAuthorize 활성화
public class SecurityConfig {
    
    // 1. 비밀번호 암호화 (BCrypt)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    // 2. 권한 계층 설정
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        String hierarchyString = """
            ROLE_SUPER_ADMIN > ROLE_ADMIN
            ROLE_ADMIN > ROLE_MANAGER
            ROLE_MANAGER > ROLE_DEV
            ROLE_DEV > ROLE_USER
            ROLE_USER > ROLE_GUEST
            """;
        hierarchy.setHierarchy(hierarchyString);
        return hierarchy;
    }
    
    // 3. 메서드 보안에 계층 적용
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = 
            new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }
    
    // 4. Security Filter Chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())  // JWT 사용 시 CSRF 불필요
            .sessionManagement(sm -> 
                sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션 사용 안 함
            )
            .authorizeHttpRequests(registry -> {
                registry.anyRequest().permitAll();  // URL 레벨은 모두 허용
                                                     // @PreAuthorize로 제어
            })
            // JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 추가
            .addFilterBefore(jwtAuthenticationFilter, 
                             UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

#### 📌 왜 CSRF를 Disable 하는가?

**CSRF (Cross-Site Request Forgery):**
- 사용자가 의도하지 않은 요청을 보내도록 하는 공격
- Cookie 기반 인증에서 문제됨

**JWT 사용 시:**
- JWT는 LocalStorage/SessionStorage에 저장
- 매 요청마다 명시적으로 헤더에 포함
- 자동으로 전송되지 않음 → CSRF 공격 불가

#### 📌 왜 Stateless인가?

**Stateful (세션 기반):**
```
1. 로그인 → 서버 메모리에 세션 저장
2. 클라이언트에 세션 ID 쿠키 전달
3. 매 요청마다 세션 ID로 서버 메모리 조회
```

**Stateless (JWT 기반):**
```
1. 로그인 → JWT 토큰 발급
2. 클라이언트가 토큰 저장
3. 매 요청마다 토큰으로 검증 (서버 상태 저장 불필요)
```

**장점:**
- 서버 확장이 쉬움 (세션 공유 불필요)
- 서버 메모리 절약

---

### 3️⃣ UserAccount - 사용자 엔티티

**역할:** 사용자 정보 저장, Spring Security와 통합

**코드 위치:** `user/UserAccount.java`

```java
@Entity
@Table(name = "users")
public class UserAccount implements UserDetails {  // Spring Security 인터페이스
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 100)
    private String username;
    
    @Column(nullable = false)
    private String password;  // BCrypt 암호화된 값
    
    @Convert(converter = RoleSetConverter.class)
    @Column(name = "roles", nullable = false, length = 255)
    private Set<Role> roles;  // DB에는 "ROLE_ADMIN,ROLE_USER" 형태로 저장
    
    // Spring Security가 사용하는 메서드들
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Set<Role> → Collection<GrantedAuthority> 변환
        return roles.stream()
            .map(r -> new SimpleGrantedAuthority(r.name()))
            .collect(Collectors.toSet());
    }
    
    @Override
    public boolean isAccountNonExpired() { return true; }
    
    @Override
    public boolean isAccountNonLocked() { return true; }
    
    @Override
    public boolean isCredentialsNonExpired() { return true; }
    
    @Override
    public boolean isEnabled() { return true; }
}
```

#### 📌 RoleSetConverter - Enum ↔ String 변환

```java
@Converter
public class RoleSetConverter implements AttributeConverter<Set<Role>, String> {
    
    // Java → DB
    @Override
    public String convertToDatabaseColumn(Set<Role> attribute) {
        // [ROLE_ADMIN, ROLE_USER] → "ROLE_ADMIN,ROLE_USER"
        return attribute.stream()
            .map(Enum::name)
            .sorted()
            .collect(Collectors.joining(","));
    }
    
    // DB → Java
    @Override
    public Set<Role> convertToEntityAttribute(String dbData) {
        // "ROLE_ADMIN,ROLE_USER" → [ROLE_ADMIN, ROLE_USER]
        return Arrays.stream(dbData.split(","))
            .map(String::trim)
            .map(Role::valueOf)
            .collect(Collectors.toSet());
    }
}
```

---

## 코드 실행 순서

### 🎬 시나리오: admin 계정으로 로그인 후 `/api/admin/panel` 접근

#### Step 1: 로그인 요청

```
POST /login
{
  "username": "admin",
  "password": "admin"
}
```

**실행 순서:**

```
1. AuthController.login() 호출
   ↓
2. AuthenticationManager.authenticate()
   ↓
3. UserDetailsService.loadUserByUsername("admin")
   ↓
4. UserRepository.findByUsername("admin")
   ↓
5. DB에서 조회: username="admin", password="$2a$10...", roles="ROLE_ADMIN"
   ↓
6. BCrypt로 비밀번호 검증: "admin" vs "$2a$10..."
   ↓
7. 검증 성공 → UserAccount 객체 반환
   ↓
8. JwtTokenProvider.generateToken("admin", [ROLE_ADMIN])
   ↓
9. JWT 토큰 생성:
   {
     "sub": "admin",
     "roles": "ROLE_ADMIN",
     "iat": 1699000000,
     "exp": 1699003600
   }
   서명 추가 → eyJhbGciOiJIUzI1NiJ9.eyJzdWIi...
   ↓
10. 클라이언트에 토큰 반환
    {"token": "eyJhbGci..."}
```

#### Step 2: 인증 API 요청

```
GET /api/admin/panel
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIi...
```

**실행 순서:**

```
1. 요청이 Spring Security Filter Chain 진입
   ↓
2. JwtAuthenticationFilter.doFilterInternal() 실행
   ↓
3. Authorization 헤더에서 토큰 추출
   "Bearer eyJhbGci..." → "eyJhbGci..."
   ↓
4. JwtTokenProvider.validateToken(token)
   - 서명 검증 (secret key로)
   - 만료 시간 체크
   → 검증 성공
   ↓
5. JwtTokenProvider.getUsername(token) → "admin"
6. JwtTokenProvider.getRoles(token) → [ROLE_ADMIN]
   ↓
7. SimpleGrantedAuthority 객체 생성
   [SimpleGrantedAuthority("ROLE_ADMIN")]
   ↓
8. Authentication 객체 생성
   UsernamePasswordAuthenticationToken(
     principal = "admin",
     credentials = null,
     authorities = [ROLE_ADMIN]
   )
   ↓
9. SecurityContext에 저장
   SecurityContextHolder.getContext().setAuthentication(authentication)
   ↓
10. 다음 필터로 진행 (filterChain.doFilter())
    ↓
11. @PreAuthorize("hasRole('ADMIN')") 체크
    - SecurityContext에서 authorities 조회
    - ROLE_ADMIN 있음? → ✅ 통과
    ↓
12. TestControllers.adminPanel() 실행
    ↓
13. 응답 반환
    {
      "message": "관리자 패널",
      "user": "admin",
      "authorities": [{"authority": "ROLE_ADMIN"}]
    }
```

---

## 보안 개념 이해

### 🔒 BCrypt 비밀번호 암호화

**왜 BCrypt를 사용하는가?**

❌ **일반 해시 (MD5, SHA-256):**
```
"password123" → MD5 → "482c811da5d5b4bc6d497ffa98491e38"
```
- 같은 입력 → 항상 같은 출력
- Rainbow Table 공격에 취약

✅ **BCrypt:**
```
"password123" + salt → BCrypt → "$2a$10$abcd...xyz"
```
- Salt(무작위 값) 추가
- 매번 다른 결과
- 계산 비용 조절 가능 (brute force 방어)

**예시:**
```java
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

// 같은 비밀번호도 매번 다른 해시
String hash1 = encoder.encode("password"); 
// $2a$10$abc...
String hash2 = encoder.encode("password"); 
// $2a$10$xyz...

// 검증은 가능
encoder.matches("password", hash1); // true
encoder.matches("password", hash2); // true
```

---

### 🎭 Role Hierarchy (권한 계층)

**계층 구조:**
```
ROLE_SUPER_ADMIN > ROLE_ADMIN > ROLE_MANAGER > ROLE_DEV > ROLE_USER > ROLE_GUEST
```

**의미:**
```java
@PreAuthorize("hasRole('USER')")  
// ROLE_USER, ROLE_DEV, ROLE_MANAGER, ROLE_ADMIN, ROLE_SUPER_ADMIN 모두 접근 가능
```

**동작 원리:**

```java
// SecurityConfig.java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy(
        "ROLE_ADMIN > ROLE_USER \n" +
        "ROLE_USER > ROLE_GUEST"
    );
    return hierarchy;
}

// 실제 검증 시
if (user.hasRole("ADMIN")) {
    // 계층으로 인해 자동으로 USER, GUEST 권한도 포함됨
    authorities = [ROLE_ADMIN, ROLE_USER, ROLE_GUEST]
}
```

---

### 🛡️ @PreAuthorize vs URL 패턴 보안

#### URL 패턴 방식 (기존)
```java
http.authorizeHttpRequests(registry -> registry
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/user/**").hasRole("USER")
);
```

**단점:**
- URL 패턴만으로 제어
- 복잡한 조건 표현 어려움

#### @PreAuthorize 방식 (현재)
```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/api/admin/panel")
public Map<String, Object> adminPanel() { }

@PreAuthorize("hasRole('ADMIN') and #username == authentication.name")
@DeleteMapping("/api/users/{username}")
public void deleteUser(@PathVariable String username) { }

@PreAuthorize("@securityService.canAccess(authentication, #id)")
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) { }
```

**장점:**
- 메서드 단위 세밀한 제어
- SpEL로 복잡한 조건 표현 가능
- 비즈니스 로직과 권한 체크 통합

---

### 🔐 JWT vs Session 비교

| 항목 | Session | JWT |
|------|---------|-----|
| **저장 위치** | 서버 메모리/Redis | 클라이언트 (LocalStorage) |
| **확장성** | 어려움 (세션 공유 필요) | 쉬움 (Stateless) |
| **성능** | DB/Cache 조회 필요 | 토큰 검증만 (빠름) |
| **크기** | 작음 (Session ID만) | 큼 (전체 정보 포함) |
| **무효화** | 쉬움 (서버에서 삭제) | 어려움 (만료 대기) |
| **보안** | Cookie HttpOnly 가능 | XSS 취약 (주의 필요) |

---

## 추가 학습 자료

### 📚 권장 학습 순서

1. **JWT 기본 개념**
   - https://jwt.io/introduction
   - Payload, Signature 이해

2. **Spring Security 아키텍처**
   - Filter Chain
   - Authentication, Authorization

3. **BCrypt 암호화**
   - Salt, Cost Factor

4. **CORS, CSRF**
   - REST API 보안

5. **실전 보안**
   - Refresh Token
   - Token Blacklist
   - Rate Limiting

---

## 🎯 핵심 요약

### JWT 인증 3단계
1. **로그인** → JWT 발급
2. **토큰 저장** → 클라이언트
3. **매 요청** → 헤더에 토큰 포함

### Spring Security 3요소
1. **Filter** → 요청 가로채기
2. **Authentication** → 인증 정보
3. **Authorization** → 권한 체크

### 보안 3원칙
1. **비밀번호 암호화** (BCrypt)
2. **토큰 서명 검증** (HMAC)
3. **권한 체크** (@PreAuthorize)

---

**이 문서는 실제 코드와 함께 학습하면 가장 효과적입니다!**

각 개념을 Swagger에서 직접 테스트해보세요:
```
http://localhost:8080/swagger-ui.html
```

Happy Learning! 🚀

