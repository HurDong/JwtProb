package com.example.jwtprob.permission;

import jakarta.persistence.*;
import java.util.Objects;

@Entity
@Table(
    name = "permissions",
    uniqueConstraints = @UniqueConstraint(columnNames = {"resource", "action"}),
    indexes = {
        @Index(name = "idx_resource", columnList = "resource"),
        @Index(name = "idx_action", columnList = "action")
    }
)
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String resource; // USER, POST, ORDER, REPORT

    @Column(nullable = false, length = 50)
    private String action; // READ, WRITE, DELETE, APPROVE, EXPORT

    @Column(length = 200)
    private String description;

    protected Permission() {
    }

    public Permission(String resource, String action, String description) {
        this.resource = resource;
        this.action = action;
        this.description = description;
    }

    public Permission(String resource, String action) {
        this(resource, action, null);
    }

    public Long getId() {
        return id;
    }

    public String getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Permission을 "RESOURCE:ACTION" 형식 문자열로 반환
     * 예: "USER:READ", "POST:DELETE"
     */
    public String getPermissionString() {
        return resource + ":" + action;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Permission that = (Permission) o;
        return Objects.equals(resource, that.resource) && 
               Objects.equals(action, that.action);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resource, action);
    }

    @Override
    public String toString() {
        return getPermissionString();
    }
}

