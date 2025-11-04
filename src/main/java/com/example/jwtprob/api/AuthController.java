package com.example.jwtprob.api;

import com.example.jwtprob.api.dto.AuthResponse;
import com.example.jwtprob.api.dto.LoginRequest;
import com.example.jwtprob.api.dto.SignupRequest;
import com.example.jwtprob.security.BlacklistService;
import com.example.jwtprob.security.JwtTokenProvider;
import com.example.jwtprob.security.RefreshTokenService;
import com.example.jwtprob.user.Role;
import com.example.jwtprob.user.UserAccount;
import com.example.jwtprob.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final BlacklistService blacklistService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            BlacklistService blacklistService,
            RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.blacklistService = blacklistService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/signup/guest")
    public ResponseEntity<?> signupGuest(@Valid @RequestBody SignupRequest request) {
        return createUser(request, Set.of(Role.ROLE_GUEST));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest request) {
        return createUser(request, Set.of(Role.ROLE_USER));
    }

    @PostMapping("/signup/dev")
    public ResponseEntity<?> signupDev(@Valid @RequestBody SignupRequest request) {
        return createUser(request, Set.of(Role.ROLE_DEV));
    }

    @PostMapping("/signup/manager")
    public ResponseEntity<?> signupManager(@Valid @RequestBody SignupRequest request) {
        return createUser(request, Set.of(Role.ROLE_MANAGER));
    }

    @PostMapping("/signup/admin")
    public ResponseEntity<?> signupAdmin(@Valid @RequestBody SignupRequest request) {
        return createUser(request, Set.of(Role.ROLE_ADMIN));
    }

    @PostMapping("/signup/superadmin")
    public ResponseEntity<?> signupSuperAdmin(@Valid @RequestBody SignupRequest request) {
        return createUser(request, Set.of(Role.ROLE_SUPER_ADMIN));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        log.info("=== 로그인 시도: username={}", request.getUsername());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            log.info("=== 인증 성공: username={}", request.getUsername());

            UserAccount principal = (UserAccount) authentication.getPrincipal();
            log.info("=== 사용자 권한: username={}, roles={}", principal.getUsername(), principal.getRoles());

            // Access Token 생성 (15분)
            String accessToken = jwtTokenProvider.generateToken(principal.getUsername(), principal.getRoles());
            log.info("=== Access Token 생성 완료: username={}, token length={}", principal.getUsername(), accessToken.length());

            // Refresh Token 생성 (7일)
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String refreshToken = refreshTokenService.createRefreshToken(principal.getUsername(), deviceInfo);
            log.info("=== Refresh Token 생성 완료: username={}", principal.getUsername());

            return ResponseEntity.ok(Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "tokenType", "Bearer",
                "expiresIn", 900 // 15분 (초 단위)
            ));
        } catch (Exception e) {
            log.error("=== 로그인 실패: username={}, error={}", request.getUsername(), e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Access Token 재발급
     * Refresh Token을 사용하여 새로운 Access Token 발급
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "Refresh Token이 필요합니다"
            ));
        }

        try {
            // Refresh Token 검증
            com.example.jwtprob.security.RefreshToken tokenEntity = refreshTokenService.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("유효하지 않은 Refresh Token입니다"));
            
            refreshTokenService.verifyExpiration(tokenEntity);
            
            // 사용자 정보 조회
            UserAccount user = userRepository.findByUsername(tokenEntity.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
            
            // 새로운 Access Token 발급
            String newAccessToken = jwtTokenProvider.generateToken(user.getUsername(), user.getRoles());
            log.info("=== Access Token 재발급 완료: username={}", user.getUsername());
            
            return ResponseEntity.ok(Map.of(
                "accessToken", newAccessToken,
                "tokenType", "Bearer",
                "expiresIn", 900 // 15분
            ));
        } catch (Exception e) {
            log.error("=== Token 재발급 실패: error={}", e.getMessage(), e);
            return ResponseEntity.status(401).body(Map.of(
                "success", false,
                "message", e.getMessage()
            ));
        }
    }

    /**
     * 일반 로그아웃 (클라이언트 방식)
     * - 서버는 단순히 성공 응답만 반환
     * - 클라이언트에서 토큰을 삭제해야 함
     * - 토큰은 만료 전까지 여전히 유효함 (보안 취약)
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader,
                                     @RequestBody(required = false) Map<String, String> body) {
        String username = null;
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            username = jwtTokenProvider.getUsername(token);
            log.info("=== 일반 로그아웃: username={}", username);
        }
        
        // Refresh Token도 삭제 (있으면)
        if (body != null && body.containsKey("refreshToken")) {
            String refreshToken = body.get("refreshToken");
            refreshTokenService.deleteByToken(refreshToken);
            log.info("=== Refresh Token 삭제: username={}", username);
        } else if (username != null) {
            // username으로 Refresh Token 삭제
            refreshTokenService.deleteByUsername(username);
            log.info("=== Refresh Token 삭제 (username 기반): username={}", username);
        }
        
        return ResponseEntity.ok(Map.of(
            "success", true,
            "message", "로그아웃 성공",
            "type", "CLIENT_LOGOUT"
        ));
    }

    /**
     * 블랙리스트 로그아웃 (서버 방식)
     * - 서버가 토큰을 블랙리스트에 추가
     * - 토큰이 즉시 무효화됨 (진짜 로그아웃)
     * - 클라이언트도 토큰을 삭제해야 함
     */
    @PostMapping("/logout/blacklist")
    public ResponseEntity<?> logoutWithBlacklist(@RequestHeader("Authorization") String authHeader,
                                                  @RequestBody(required = false) Map<String, String> body) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "Authorization 헤더가 필요합니다"
            ));
        }

        String token = authHeader.substring(7);
        String username = jwtTokenProvider.getUsername(token);
        
        try {
            // Access Token 블랙리스트에 추가
            blacklistService.addToBlacklist(token, "LOGOUT");
            log.info("=== 블랙리스트 로그아웃 성공: username={}", username);
            
            // Refresh Token도 삭제
            if (body != null && body.containsKey("refreshToken")) {
                String refreshToken = body.get("refreshToken");
                refreshTokenService.deleteByToken(refreshToken);
                log.info("=== Refresh Token 삭제: username={}", username);
            } else {
                refreshTokenService.deleteByUsername(username);
                log.info("=== Refresh Token 삭제 (username 기반): username={}", username);
            }
            
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "로그아웃 성공 (토큰이 무효화되었습니다)",
                "type", "BLACKLIST_LOGOUT",
                "username", username
            ));
        } catch (Exception e) {
            log.error("=== 블랙리스트 로그아웃 실패: username={}, error={}", username, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "message", "로그아웃 처리 중 오류가 발생했습니다"
            ));
        }
    }

    private ResponseEntity<?> createUser(SignupRequest request, Set<Role> roles) {
        log.info("=== 회원가입 시도: username={}, roles={}", request.getUsername(), roles);

        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("=== 회원가입 실패: 이미 존재하는 사용자명 - username={}", request.getUsername());
            return ResponseEntity.badRequest()
                    .body(new com.example.jwtprob.api.dto.ApiResponse("이미 존재하는 사용자명입니다."));
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());
        log.info("=== 비밀번호 암호화 완료: username={}", request.getUsername());

        UserAccount user = new UserAccount(
                request.getUsername(),
                encodedPassword,
                roles);
        userRepository.save(user);
        log.info("=== 회원가입 성공: username={}, roles={}", request.getUsername(), roles);

        String rolesStr = roles.stream().map(Enum::name).collect(Collectors.joining(", "));
        return ResponseEntity.ok(new com.example.jwtprob.api.dto.ApiResponse("회원가입 완료 (" + rolesStr + ")"));
    }
}
