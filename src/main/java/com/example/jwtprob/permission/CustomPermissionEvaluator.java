package com.example.jwtprob.permission;

import com.example.jwtprob.user.UserAccountV2;
import com.example.jwtprob.user.UserAccountV2Repository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private static final Logger log = LoggerFactory.getLogger(CustomPermissionEvaluator.class);

    private final UserAccountV2Repository userRepository;

    public CustomPermissionEvaluator(UserAccountV2Repository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * @PreAuthorize("hasPermission('USER', 'DELETE')") 형태로 사용
     * 
     * @param auth 인증 정보
     * @param targetDomainObject 리소스 (예: "USER")
     * @param permission 액션 (예: "DELETE")
     */
    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        if (auth == null || !auth.isAuthenticated()) {
            log.debug("인증되지 않음");
            return false;
        }

        String username = auth.getName();
        String resource = targetDomainObject.toString();
        String action = permission.toString();

        log.debug("권한 검증: username={}, resource={}, action={}", username, resource, action);

        // DB에서 사용자 조회 (Role + Permission 포함)
        UserAccountV2 user = userRepository.findByUsernameWithRolesAndPermissions(username)
            .orElse(null);

        if (user == null) {
            log.warn("사용자 없음: username={}", username);
            return false;
        }

        // Permission 확인
        boolean hasPermission = user.hasPermission(resource, action);
        
        if (hasPermission) {
            log.info("✓ 권한 있음: username={}, permission={}:{}", username, resource, action);
        } else {
            log.warn("✗ 권한 없음: username={}, permission={}:{}", username, resource, action);
        }

        return hasPermission;
    }

    /**
     * @PreAuthorize("hasPermission(#user, 'DELETE')") 형태로 사용
     * (현재 프로젝트에선 미사용)
     */
    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        log.debug("hasPermission(targetId) 호출: targetId={}, targetType={}, permission={}", 
                  targetId, targetType, permission);
        return false;
    }
}

