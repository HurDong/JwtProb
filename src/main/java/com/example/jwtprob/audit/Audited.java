package com.example.jwtprob.audit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 메서드에 이 어노테이션을 붙이면 자동으로 감사 로그 생성
 * 
 * 사용 예시:
 * @Audited(action = "USER_DELETE", resource = "User")
 * public void deleteUser(Long id) { ... }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    
    /**
     * 수행한 액션 설명
     * 예: "USER_CREATE", "POST_DELETE", "ORDER_APPROVE"
     */
    String action() default "";
    
    /**
     * 대상 리소스
     * 예: "User", "Post", "Order"
     */
    String resource() default "";
    
    /**
     * 추가 설명 (옵션)
     */
    String description() default "";
}

