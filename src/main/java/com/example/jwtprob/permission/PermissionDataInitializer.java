package com.example.jwtprob.permission;

import com.example.jwtprob.user.UserAccountV2;
import com.example.jwtprob.user.UserAccountV2Repository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@Order(2) // DataInitializer(Order 1) 다음에 실행
public class PermissionDataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(PermissionDataInitializer.class);

    private final PermissionRepository permissionRepository;
    private final RoleEntityRepository roleRepository;
    private final UserAccountV2Repository userRepository;
    private final PasswordEncoder passwordEncoder;

    public PermissionDataInitializer(
            PermissionRepository permissionRepository,
            RoleEntityRepository roleRepository,
            UserAccountV2Repository userRepository,
            PasswordEncoder passwordEncoder) {
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        log.info("========================================");
        log.info("Permission-Based Security 초기화 시작");
        log.info("========================================");

        // 1. Permission 생성
        if (permissionRepository.count() == 0) {
            initializePermissions();
        } else {
            log.info("Permissions 이미 존재 ({}개), 생략", permissionRepository.count());
        }

        // 2. Role 생성
        if (roleRepository.count() == 0) {
            initializeRoles();
        } else {
            log.info("Roles 이미 존재 ({}개), 생략", roleRepository.count());
        }

        // 3. 테스트 사용자 생성
        if (userRepository.count() == 0) {
            initializeUsers();
        } else {
            log.info("Users 이미 존재 ({}개), 생략", userRepository.count());
        }

        log.info("========================================");
        log.info("Permission-Based Security 초기화 완료!");
        log.info("========================================");
    }

    private void initializePermissions() {
        log.info("→ Permissions 생성 중...");

        List<Permission> permissions = List.of(
            // USER 리소스
            new Permission("USER", "READ", "사용자 조회"),
            new Permission("USER", "WRITE", "사용자 생성/수정"),
            new Permission("USER", "DELETE", "사용자 삭제"),
            
            // POST 리소스
            new Permission("POST", "READ", "게시글 조회"),
            new Permission("POST", "WRITE", "게시글 생성/수정"),
            new Permission("POST", "DELETE", "게시글 삭제"),
            
            // COMMENT 리소스
            new Permission("COMMENT", "READ", "댓글 조회"),
            new Permission("COMMENT", "WRITE", "댓글 작성"),
            new Permission("COMMENT", "DELETE", "댓글 삭제"),
            
            // ORDER 리소스
            new Permission("ORDER", "READ", "주문 조회"),
            new Permission("ORDER", "WRITE", "주문 생성"),
            new Permission("ORDER", "APPROVE", "주문 승인"),
            new Permission("ORDER", "CANCEL", "주문 취소"),
            
            // REPORT 리소스
            new Permission("REPORT", "READ", "보고서 조회"),
            new Permission("REPORT", "WRITE", "보고서 작성"),
            new Permission("REPORT", "EXPORT", "보고서 내보내기")
        );

        permissionRepository.saveAll(permissions);
        log.info("✓ Permissions 생성 완료: {} 개", permissions.size());
    }

    private void initializeRoles() {
        log.info("→ Roles 생성 중...");

        // Permission 조회 헬퍼
        Permission userRead = findPermission("USER", "READ");
        Permission userWrite = findPermission("USER", "WRITE");
        Permission userDelete = findPermission("USER", "DELETE");
        
        Permission postRead = findPermission("POST", "READ");
        Permission postWrite = findPermission("POST", "WRITE");
        Permission postDelete = findPermission("POST", "DELETE");
        
        Permission commentRead = findPermission("COMMENT", "READ");
        Permission commentWrite = findPermission("COMMENT", "WRITE");
        Permission commentDelete = findPermission("COMMENT", "DELETE");
        
        Permission orderRead = findPermission("ORDER", "READ");
        Permission orderWrite = findPermission("ORDER", "WRITE");
        Permission orderApprove = findPermission("ORDER", "APPROVE");
        
        Permission reportRead = findPermission("REPORT", "READ");
        Permission reportExport = findPermission("REPORT", "EXPORT");

        // 1. USER_MANAGER: 사용자 관리자
        RoleEntity userManager = new RoleEntity("ROLE_USER_MANAGER", "사용자 관리자 (조회/수정만 가능)");
        userManager.addPermissions(userRead, userWrite);  // DELETE 없음!
        roleRepository.save(userManager);
        log.info("  - ROLE_USER_MANAGER: USER:READ, USER:WRITE");

        // 2. CONTENT_MANAGER: 콘텐츠 관리자
        RoleEntity contentManager = new RoleEntity("ROLE_CONTENT_MANAGER", "콘텐츠 관리자");
        contentManager.addPermissions(postRead, postWrite, postDelete, commentRead, commentDelete);
        roleRepository.save(contentManager);
        log.info("  - ROLE_CONTENT_MANAGER: POST:*, COMMENT:READ/DELETE");

        // 3. ORDER_MANAGER: 주문 관리자
        RoleEntity orderManager = new RoleEntity("ROLE_ORDER_MANAGER", "주문 관리자");
        orderManager.addPermissions(orderRead, orderWrite, orderApprove);
        roleRepository.save(orderManager);
        log.info("  - ROLE_ORDER_MANAGER: ORDER:READ/WRITE/APPROVE");

        // 4. ANALYST: 분석가 (조회 전용)
        RoleEntity analyst = new RoleEntity("ROLE_ANALYST", "분석가 (읽기 전용)");
        analyst.addPermissions(userRead, postRead, commentRead, orderRead, reportRead, reportExport);
        roleRepository.save(analyst);
        log.info("  - ROLE_ANALYST: 모든 리소스 READ + REPORT:EXPORT");

        // 5. SUPER_ADMIN: 최고 관리자 (모든 권한)
        RoleEntity superAdmin = new RoleEntity("ROLE_SUPER_ADMIN", "최고 관리자 (모든 권한)");
        superAdmin.addPermissions(permissionRepository.findAll().toArray(new Permission[0]));
        roleRepository.save(superAdmin);
        log.info("  - ROLE_SUPER_ADMIN: 모든 권한 ({} 개)", superAdmin.getPermissions().size());

        log.info("✓ Roles 생성 완료: 5개");
    }

    private void initializeUsers() {
        log.info("→ 테스트 사용자 생성 중...");

        // 1. 사용자 관리자
        UserAccountV2 userManager = new UserAccountV2("usermgr", passwordEncoder.encode("usermgr"));
        userManager.addRole(roleRepository.findByName("ROLE_USER_MANAGER").orElseThrow());
        userRepository.save(userManager);
        log.info("  - usermgr/usermgr → ROLE_USER_MANAGER");

        // 2. 콘텐츠 관리자
        UserAccountV2 contentManager = new UserAccountV2("contentmgr", passwordEncoder.encode("contentmgr"));
        contentManager.addRole(roleRepository.findByName("ROLE_CONTENT_MANAGER").orElseThrow());
        userRepository.save(contentManager);
        log.info("  - contentmgr/contentmgr → ROLE_CONTENT_MANAGER");

        // 3. 주문 관리자
        UserAccountV2 orderManager = new UserAccountV2("ordermgr", passwordEncoder.encode("ordermgr"));
        orderManager.addRole(roleRepository.findByName("ROLE_ORDER_MANAGER").orElseThrow());
        userRepository.save(orderManager);
        log.info("  - ordermgr/ordermgr → ROLE_ORDER_MANAGER");

        // 4. 분석가
        UserAccountV2 analyst = new UserAccountV2("analyst", passwordEncoder.encode("analyst"));
        analyst.addRole(roleRepository.findByName("ROLE_ANALYST").orElseThrow());
        userRepository.save(analyst);
        log.info("  - analyst/analyst → ROLE_ANALYST");

        // 5. 슈퍼 관리자
        UserAccountV2 superadmin = new UserAccountV2("superadmin2", passwordEncoder.encode("superadmin2"));
        superadmin.addRole(roleRepository.findByName("ROLE_SUPER_ADMIN").orElseThrow());
        userRepository.save(superadmin);
        log.info("  - superadmin2/superadmin2 → ROLE_SUPER_ADMIN");

        // 6. 복합 권한 (사용자 + 콘텐츠 관리자)
        UserAccountV2 multiRole = new UserAccountV2("multimgr", passwordEncoder.encode("multimgr"));
        multiRole.addRole(roleRepository.findByName("ROLE_USER_MANAGER").orElseThrow());
        multiRole.addRole(roleRepository.findByName("ROLE_CONTENT_MANAGER").orElseThrow());
        userRepository.save(multiRole);
        log.info("  - multimgr/multimgr → USER_MANAGER + CONTENT_MANAGER");

        log.info("✓ 테스트 사용자 생성 완료: 6명");
    }

    private Permission findPermission(String resource, String action) {
        return permissionRepository.findByResourceAndAction(resource, action)
            .orElseThrow(() -> new RuntimeException("Permission not found: " + resource + ":" + action));
    }
}

