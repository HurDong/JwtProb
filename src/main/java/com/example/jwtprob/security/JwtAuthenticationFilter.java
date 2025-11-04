package com.example.jwtprob.security;

import com.example.jwtprob.user.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String requestURI = request.getRequestURI();
        log.debug("=== JWT 필터 실행: method={}, uri={}", request.getMethod(), requestURI);

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            log.info("=== JWT 토큰 발견: uri={}, token length={}", requestURI, token.length());

            if (jwtTokenProvider.validateToken(token)) {
                String username = jwtTokenProvider.getUsername(token);
                Set<Role> roles = jwtTokenProvider.getRoles(token);
                log.info("=== JWT 토큰 검증 성공: username={}, roles={}", username, roles);

                var authorities = roles.stream().map(r -> new SimpleGrantedAuthority(r.name()))
                        .collect(Collectors.toSet());
                var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("=== SecurityContext에 인증 정보 저장 완료: username={}, authorities={}", username, authorities);
            } else {
                log.warn("=== JWT 토큰 검증 실패: uri={}", requestURI);
            }
        } else {
            log.debug("=== JWT 토큰 없음: uri={}", requestURI);
        }
        filterChain.doFilter(request, response);
    }
}
