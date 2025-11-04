package com.example.jwtprob.api;

import com.example.jwtprob.api.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v2")
public class PermissionTestController {

    // ========== USER 리소스 ==========
    
    @GetMapping("/users")
    @PreAuthorize("hasPermission('USER', 'READ')")
    public ResponseEntity<?> getUsers(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "사용자 목록 조회 성공",
            Map.of("users", "[user1, user2, user3]", "requester", auth.getName())
        ));
    }

    @PostMapping("/users")
    @PreAuthorize("hasPermission('USER', 'WRITE')")
    public ResponseEntity<?> createUser(@RequestBody Map<String, String> body, Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "사용자 생성 성공",
            Map.of("newUser", body.get("username"), "createdBy", auth.getName())
        ));
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasPermission('USER', 'DELETE')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id, Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "사용자 삭제 성공",
            Map.of("deletedUserId", id, "deletedBy", auth.getName())
        ));
    }

    // ========== POST 리소스 ==========
    
    @GetMapping("/posts")
    @PreAuthorize("hasPermission('POST', 'READ')")
    public ResponseEntity<?> getPosts(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "게시글 목록 조회 성공",
            Map.of("posts", "[post1, post2]", "requester", auth.getName())
        ));
    }

    @PostMapping("/posts")
    @PreAuthorize("hasPermission('POST', 'WRITE')")
    public ResponseEntity<?> createPost(@RequestBody Map<String, String> body, Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "게시글 작성 성공",
            Map.of("postTitle", body.get("title"), "author", auth.getName())
        ));
    }

    @DeleteMapping("/posts/{id}")
    @PreAuthorize("hasPermission('POST', 'DELETE')")
    public ResponseEntity<?> deletePost(@PathVariable Long id, Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "게시글 삭제 성공",
            Map.of("deletedPostId", id, "deletedBy", auth.getName())
        ));
    }

    // ========== ORDER 리소스 ==========
    
    @GetMapping("/orders")
    @PreAuthorize("hasPermission('ORDER', 'READ')")
    public ResponseEntity<?> getOrders(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "주문 목록 조회 성공",
            Map.of("orders", "[order1, order2]", "requester", auth.getName())
        ));
    }

    @PostMapping("/orders/{id}/approve")
    @PreAuthorize("hasPermission('ORDER', 'APPROVE')")
    public ResponseEntity<?> approveOrder(@PathVariable Long id, Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "주문 승인 완료",
            Map.of("orderId", id, "approvedBy", auth.getName())
        ));
    }

    // ========== REPORT 리소스 ==========
    
    @GetMapping("/reports")
    @PreAuthorize("hasPermission('REPORT', 'READ')")
    public ResponseEntity<?> getReports(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "보고서 조회 성공",
            Map.of("reports", "[report1, report2]", "requester", auth.getName())
        ));
    }

    @PostMapping("/reports/export")
    @PreAuthorize("hasPermission('REPORT', 'EXPORT')")
    public ResponseEntity<?> exportReport(@RequestBody Map<String, String> body, Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "보고서 내보내기 성공",
            Map.of("format", body.get("format"), "exportedBy", auth.getName())
        ));
    }

    // ========== 권한 확인 API ==========
    
    @GetMapping("/my-permissions")
    public ResponseEntity<?> getMyPermissions(Authentication auth) {
        return ResponseEntity.ok(ApiResponse.success(
            "내 권한 정보",
            Map.of(
                "username", auth.getName(),
                "authorities", auth.getAuthorities()
            )
        ));
    }
}

