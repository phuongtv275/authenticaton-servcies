package com.example.identityservice.security.jwt;


import com.example.identityservice.models.entities.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtils {
    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.access-token-expiration:900000}")
    private Long accessTokenExpiration;

    private Key signKey;

    @PostConstruct
    public void init() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.signKey = Keys.hmacShaKeyFor(bytes);
    }

    // Lấy signing key từ Base64 secret (HMAC-SHA256 >= 256 bits)
    public Key getSignKey() {
        if (this.signKey == null) {
            init();
        }
        return this.signKey;
    }

    /**
     * Tạo Access Token (JWT) ngắn hạn chứa thông tin người dùng và vai trò (roles).
     *
     * @param user đối tượng User chứa thông tin tài khoản và danh sách quyền
     * @return chuỗi JWT Access Token
     */
    public String generateAccessToken(User user) {
        List<String> roleNames = user.getRoles() != null
                ? user.getRoles().stream()
                    .map(role -> role.getRoleName().name())
                    .toList()
                : List.of();

        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("roles", roleNames);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Giữ lại generateToken để tương thích ngược
    public String generateToken(User user) {
        return generateAccessToken(user);
    }
}
