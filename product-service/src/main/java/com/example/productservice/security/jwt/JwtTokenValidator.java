package com.example.productservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collections;
import java.util.List;

/**
 * Validator và parser JWT cho Downstream Service (Product-Service).
 * Sử dụng chung Secret Key với Identity-Service và API Gateway.
 */
@Slf4j
@Component
public class JwtTokenValidator {

    @Value("${app.jwt.secret}")
    private String secretKey;

    private Key signKey;

    @PostConstruct
    public void init() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.signKey = Keys.hmacShaKeyFor(bytes);
        log.info("JwtTokenValidator initialized successfully with HMAC-SHA256 key");
    }

    public Key getSignKey() {
        if (this.signKey == null) {
            init();
        }
        return this.signKey;
    }

    /**
     * Xác thực tính hợp lệ và chữ ký của chuỗi token.
     *
     * @param token chuỗi JWT
     * @return true nếu token hợp lệ, false nếu hết hạn hoặc sai chữ ký
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Trích xuất toàn bộ Claims từ token JWT hợp lệ.
     *
     * @param token chuỗi JWT
     * @return đối tượng Claims
     */
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Trích xuất username (subject) từ token.
     */
    public String getUsername(String token) {
        Claims claims = getClaims(token);
        String username = claims.get("username", String.class);
        return username != null ? username : claims.getSubject();
    }

    /**
     * Trích xuất danh sách vai trò (roles) từ Claims.
     */
    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        Claims claims = getClaims(token);
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof List<?>) {
            return ((List<?>) rolesObj).stream()
                    .map(Object::toString)
                    .toList();
        }
        return Collections.emptyList();
    }
}
