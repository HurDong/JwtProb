package com.example.jwtprob.security;

import com.example.jwtprob.user.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private final JwtProperties properties;
    private final Key key;

    public JwtTokenProvider(JwtProperties properties) {
        this.properties = properties;
        byte[] keyBytes = Decoders.BASE64.decode(ensureBase64(properties.getSecret()));
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String username, Set<Role> roles) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + properties.getExpirationMs());
        String rolesCsv = roles.stream().map(Enum::name).sorted().collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(username)
                .addClaims(Map.of("roles", rolesCsv))
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsername(String token) {
        return parseClaims(token).getBody().getSubject();
    }

    public Set<Role> getRoles(String token) {
        Claims claims = parseClaims(token).getBody();
        Object rolesObj = claims.get("roles");
        if (rolesObj == null) return Set.of();
        String csv = String.valueOf(rolesObj);
        if (csv.isBlank()) return Set.of();
        return Set.of(csv.split(",")).stream().map(String::trim).filter(s -> !s.isEmpty()).map(Role::valueOf).collect(Collectors.toSet());
    }

    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    private String ensureBase64(String value) {
        // jjwt Keys.hmacShaKeyFor expects raw key bytes; we'll accept plain or base64.
        // If not base64, convert to base64 to create key bytes consistently.
        try {
            Decoders.BASE64.decode(value);
            return value; // already base64
        } catch (Exception e) {
            return java.util.Base64.getEncoder().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}


