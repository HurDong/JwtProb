package com.example.jwtprob.user;

import com.example.jwtprob.permission.Permission;
import com.example.jwtprob.permission.RoleEntity;
import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users_v2")
public class UserAccountV2 implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_name")
    )
    private Set<RoleEntity> roles = new HashSet<>();

    protected UserAccountV2() {
    }

    public UserAccountV2(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public Set<RoleEntity> getRoles() {
        return roles;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void addRole(RoleEntity role) {
        this.roles.add(role);
    }

    public void addRoles(RoleEntity... roles) {
        for (RoleEntity role : roles) {
            this.roles.add(role);
        }
    }

    public void setRoles(Set<RoleEntity> roles) {
        this.roles = roles;
    }

    /**
     * 모든 Role에서 Permission 추출
     */
    public Set<Permission> getAllPermissions() {
        return roles.stream()
            .flatMap(role -> role.getPermissions().stream())
            .collect(Collectors.toSet());
    }

    /**
     * 특정 Permission 보유 여부 확인
     */
    public boolean hasPermission(String resource, String action) {
        return getAllPermissions().stream()
            .anyMatch(p -> p.getResource().equals(resource) && 
                          p.getAction().equals(action));
    }

    /**
     * Spring Security GrantedAuthority 반환
     * Role 이름들을 Authority로 변환
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Role 추가
        for (RoleEntity role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        
        // Permission도 Authority로 추가 (선택적)
        for (Permission permission : getAllPermissions()) {
            authorities.add(new SimpleGrantedAuthority(permission.getPermissionString()));
        }
        
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserAccountV2 that = (UserAccountV2) o;
        return Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username);
    }

    @Override
    public String toString() {
        return "UserAccountV2{username='" + username + "', roles=" + roles + "}";
    }
}

