package com.example.productservice.security.filter;

import com.example.productservice.security.jwt.JwtTokenValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Filter bắt chuỗi Bearer JWT từ Authorization Header, xác thực chữ ký và trích xuất roles,
 * nạp Authentication vào SecurityContextHolder cho downstream requests.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenValidator jwtTokenValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request);

        if (StringUtils.hasText(token) && jwtTokenValidator.validateToken(token)) {
            String username = jwtTokenValidator.getUsername(token);
            List<String> rawRoles = jwtTokenValidator.getRoles(token);

            // Chuyển đổi roles sang SimpleGrantedAuthority.
            // Đảm bảo hỗ trợ cả hasRole('ADMIN') (cần prefix ROLE_) và hasAuthority('ROLE_ADMIN')
            Set<SimpleGrantedAuthority> authorities = new HashSet<>();
            for (String role : rawRoles) {
                if (!StringUtils.hasText(role)) {
                    continue;
                }
                authorities.add(new SimpleGrantedAuthority(role));
                if (!role.startsWith("ROLE_")) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                }
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Authenticated user '{}' with authorities: {}", username, authorities);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Trích xuất JWT từ request header "Authorization: Bearer <token>".
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
    }
}
