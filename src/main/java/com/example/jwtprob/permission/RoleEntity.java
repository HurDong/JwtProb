package com.example.jwtprob.permission;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "roles")
public class RoleEntity {

    @Id
    @Column(length = 50)
    private String name; // ROLE_USER_MANAGER, ROLE_CONTENT_MANAGER

    @Column(length = 200)
    private String description;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "role_permissions",
        joinColumns = @JoinColumn(name = "role_name"),
        inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions = new HashSet<>();

    protected RoleEntity() {
    }

    public RoleEntity(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void addPermission(Permission permission) {
        this.permissions.add(permission);
    }

    public void addPermissions(Permission... permissions) {
        for (Permission permission : permissions) {
            this.permissions.add(permission);
        }
    }

    public void addPermissions(Set<Permission> permissions) {
        this.permissions.addAll(permissions);
    }

    /**
     * 이 Role이 특정 Permission을 가지고 있는지 확인
     */
    public boolean hasPermission(String resource, String action) {
        return permissions.stream()
            .anyMatch(p -> p.getResource().equals(resource) && 
                          p.getAction().equals(action));
    }

    /**
     * 모든 Permission을 "RESOURCE:ACTION" 형식 Set으로 반환
     */
    public Set<String> getPermissionStrings() {
        return permissions.stream()
            .map(Permission::getPermissionString)
            .collect(Collectors.toSet());
    }

    @Override
    public String toString() {
        return name + " (" + permissions.size() + " permissions)";
    }
}

